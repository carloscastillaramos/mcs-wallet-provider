package pe.gob.mtc.walletprovider.institutional;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** XLSX -> staging cifrado -> aprobación MESA_PARTES_APROBADOR -> alta atómica. Sin claves ni DNI en las respuestas. */
@Service
@ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
public class MtcPortalImportService {
    private static final String[] HEADER = {"DNI", "CODIGO_INSTITUCIONAL", "UNIDAD", "VIGENCIA_HASTA"};
    private static final int MAX_BYTES = 1_048_576;
    private static final int MAX_ROWS = 500;
    private final JdbcTemplate jdbc;
    private final HolderIdentityCrypto crypto;
    private final MtcPortalAdministration admin;

    public MtcPortalImportService(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                  MtcPortalAdministration admin) {
        this.jdbc = jdbc; this.crypto = crypto; this.admin = admin;
    }
    public record ImportResult(UUID id, String status, int rows, int created, int duplicates) { }
    private record Entry(int row, MtcPortalAdministration.CreateGrant grant) { }

    @Transactional
    public ImportResult validateAndStage(String code, MultipartFile file, String idempotency,
                                          MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        if (file == null || file.isEmpty() || file.getSize() > MAX_BYTES ||
            idempotency == null || !idempotency.matches("[A-Za-z0-9_.-]{12,100}")) throw bad();
        byte[] bytes;
        try { bytes = file.getBytes(); }
        catch (Exception ex) { throw bad(); }
        if (bytes.length > MAX_BYTES || bytes.length < 10) throw bad();
        byte[] hash = sha256(bytes);
        List<ImportResult> prior = jdbc.query("""
            SELECT id, status, COALESCE((summary->>'rows')::int, 0) AS total,
              COALESCE((summary->>'created')::int, 0) AS created,
              COALESCE((summary->>'duplicates')::int, 0) AS duplicates,
              file_hash
            FROM wallet_provider.wp_import_batch
            WHERE entity_id = ? AND idempotency_key = ?
            """, (rs, n) -> {
              if (!MessageDigest.isEqual(hash, rs.getBytes("file_hash")))
                  throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency conflict");
              return new ImportResult(rs.getObject("id", UUID.class), rs.getString("status"),
                rs.getInt("total"), rs.getInt("created"), rs.getInt("duplicates"));
            }, entity, idempotency);
        if (!prior.isEmpty()) return prior.getFirst();
        List<Entry> records = parse(bytes);
        UUID id = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO wallet_provider.wp_import_batch
            (id, entity_id, actor_issuer, actor_sub, mode, schema_version,
             file_hash, idempotency_key, status, summary)
            VALUES (?, ?, ?, ?, 'ALTA', '1', ?, ?, 'VALIDATED',
                jsonb_build_object('rows',?,'created',0,'duplicates',0))
            """, id, entity, actor.issuer(), actor.subject(), hash, idempotency, records.size());
        for (Entry entry : records) {
            var grant = entry.grant();
            String payload = grant.dni() + "|" + grant.institutionalCode() + "|" +
                (grant.unit() == null ? "" : grant.unit()) + "|" + grant.validUntil();
            jdbc.update("""
                INSERT INTO wallet_provider.wp_import_row
                    (batch_id, row_no, dni_hmac, encrypted_payload, action, result)
                VALUES (?, ?, ?, ?, 'ALTA', 'VALID')
                """, id, entry.row(), crypto.indexDni(grant.dni()),
                crypto.encryptImportRow(payload));
        }
        admin.audit(actor, entity, "IMPORT_STAGE", id.toString(), "VALIDATED", null);
        return new ImportResult(id, "VALIDATED", records.size(), 0, 0);
    }

    @Transactional(readOnly = true)
    public List<ImportResult> list(String code) {
        UUID entity = admin.activeEntity(code).id();
        return jdbc.query("""
            SELECT id, status, COALESCE((summary->>'rows')::int, 0) AS total,
              COALESCE((summary->>'created')::int, 0) AS created,
              COALESCE((summary->>'duplicates')::int, 0) AS duplicates
            FROM wallet_provider.wp_import_batch
            WHERE entity_id = ? ORDER BY CASE WHEN status = 'VALIDATED' THEN 0 ELSE 1 END,
                created_at DESC, id DESC LIMIT 200
            """, (rs, n) -> new ImportResult(rs.getObject("id", UUID.class),
                rs.getString("status"), rs.getInt("total"),
                rs.getInt("created"), rs.getInt("duplicates")), entity);
    }

    @Transactional
    public ImportResult apply(String code, UUID id, MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        if (id == null) throw bad();
        record Batch(String state, int rows, int created, int duplicates) { }
        List<Batch> batches = jdbc.query("""
            SELECT status, COALESCE((summary->>'rows')::int,0) AS total,
                COALESCE((summary->>'created')::int,0) AS created,
                COALESCE((summary->>'duplicates')::int,0) AS duplicates
            FROM wallet_provider.wp_import_batch WHERE id = ? AND entity_id = ? FOR UPDATE
            """, (rs,n) -> new Batch(rs.getString("status"), rs.getInt("total"),
                 rs.getInt("created"), rs.getInt("duplicates")), id, entity);
        if (batches.size() != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        Batch batch = batches.getFirst();
        if ("APPLIED".equals(batch.state()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El lote ya fue aplicado");
        if (!"VALIDATED".equals(batch.state())) throw new ResponseStatusException(HttpStatus.CONFLICT);
        List<byte[]> payloads = jdbc.query("""
            SELECT encrypted_payload FROM wallet_provider.wp_import_row
            WHERE batch_id = ? ORDER BY row_no FOR UPDATE
            """, (rs,n) -> rs.getBytes(1), id);
        if (payloads.size() != batch.rows() || payloads.isEmpty() || payloads.size() > MAX_ROWS)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Incomplete batch");
        int created = 0, duplicates = 0;
        for (byte[] payload : payloads) {
            String[] fields = crypto.decryptImportRow(payload).split("\\|", -1);
            if (fields.length != 4) throw bad();
            var grant = new MtcPortalAdministration.CreateGrant(fields[0], fields[1], fields[2],
                LocalDate.parse(fields[3]));
            MtcPortalAdministration.validate(grant); // Re-validate at apply time.
            if (admin.add(entity, grant) == null) duplicates++;
            else created++;
        }
        jdbc.update("""
            UPDATE wallet_provider.wp_import_batch SET status = 'APPLIED', version = version + 1,
                updated_at = CURRENT_TIMESTAMP, decided_by = ?, decided_at = CURRENT_TIMESTAMP,
                summary = jsonb_build_object('rows',?, 'created',?, 'duplicates',?)
            WHERE id = ? AND status = 'VALIDATED'
            """, actor.id(), batch.rows(), created, duplicates, id);
        // Retain ciphertext for auditable lineage, never expose it to UI.
        admin.audit(actor, entity, "IMPORT_APPLY", id.toString(), "APPLIED", null);
        return new ImportResult(id, "APPLIED", batch.rows(), created, duplicates);
    }

    @Transactional
    public void reject(String code, UUID id, String reason, MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        MtcWorkRequestService.validateReason(reason);
        if (id == null) throw bad();
        List<String> state = jdbc.query("""
            SELECT status FROM wallet_provider.wp_import_batch
            WHERE id = ? AND entity_id = ? FOR UPDATE
            """, (rs, n) -> rs.getString(1), id, entity);
        if (state.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!"VALIDATED".equals(state.getFirst()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El lote ya fue decidido");
        int rows = jdbc.update("""
            UPDATE wallet_provider.wp_import_batch
            SET status = 'REJECTED', decided_by = ?, decided_at = CURRENT_TIMESTAMP,
                decision_reason = ?, updated_at = CURRENT_TIMESTAMP, version = version + 1
            WHERE id = ? AND entity_id = ? AND status = 'VALIDATED'
            """, actor.id(), reason.trim(), id, entity);
        if (rows != 1) throw new ResponseStatusException(HttpStatus.CONFLICT);
        admin.audit(actor, entity, "IMPORT_REJECT", id.toString(), "REJECTED", reason.trim());
    }

    private static List<Entry> parse(byte[] bytes) {
        try (var wb = new XSSFWorkbook(new ByteArrayInputStream(bytes))) {
            if (wb.getNumberOfSheets() != 1) throw bad();
            Sheet sheet = wb.getSheetAt(0);
            if (sheet.getPhysicalNumberOfRows() < 2 || sheet.getLastRowNum() > MAX_ROWS)
                throw bad();
            Row header = sheet.getRow(0);
            if (header == null || header.getLastCellNum() != HEADER.length) throw bad();
            for (int j = 0; j < HEADER.length; j++)
                if (!HEADER[j].equals(textCell(header.getCell(j)))) throw bad();
            List<Entry> entries = new ArrayList<>();
            for (int r = 1; r <= sheet.getLastRowNum(); r++) {
                Row row = sheet.getRow(r);
                if (row == null || row.getLastCellNum() > HEADER.length) throw bad();
                String dni = textCell(row.getCell(0));
                String code = textCell(row.getCell(1));
                String unit = textCell(row.getCell(2));
                String date = textCell(row.getCell(3));
                var entry = new MtcPortalAdministration.CreateGrant(dni, code, unit, LocalDate.parse(date));
                MtcPortalAdministration.validate(entry);
                entries.add(new Entry(r, entry));
            }
            if (entries.isEmpty()) throw bad();
            return entries;
        } catch (ResponseStatusException ex) { throw ex; }
          catch (Exception ex) { throw bad(); }
    }
    /** Force explicit text cells: Excel's numeric DNI conversion loses leading zeros. */
    private static String textCell(Cell cell) {
        if (cell == null || cell.getCellType() != CellType.STRING ||
            cell.getStringCellValue() == null || cell.getStringCellValue().length() > 200)
            throw bad();
        return cell.getStringCellValue().trim();
    }
    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
    private static ResponseStatusException bad() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid standardized XLSX");
    }
}
