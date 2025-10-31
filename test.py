#!/usr/bin/env python3
"""
test.py (verify_pdf_full replacement)
Xác thực chữ ký PDF theo 8 bước:
 1) Read Signature dictionary (/Contents, /ByteRange)
 2) Extract PKCS#7 and check format
 3) Compute hash over ByteRange and compare messageDigest
 4) Verify signature with public key from certificate
 5) Simple chain check vs trust anchors
 6) Attempt OCSP check (if AIA OCSP present)
 7) Check RFC3161 timestamp token presence
 8) Detect incremental updates (data after ByteRange)
Ghi log chi tiết vào verify_log.txt
Usage:
  python test.py signed.pdf [trust_anchor1.pem trust_anchor2.pem ...]
Notes:
  - Requires: PyPDF2, asn1crypto, cryptography, requests (optional for OCSP)
    pip install PyPDF2 asn1crypto cryptography requests
"""
import os
import sys
import binascii
import hashlib
import datetime
import traceback
from typing import List, Tuple, Optional

try:
    import requests
except Exception:
    requests = None

from PyPDF2 import PdfReader
from asn1crypto import cms, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response

LOG_FILE = "verify_log.txt"

def log(msg: str):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def clear_log():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

# 1) Find signature dictionary (first signature field)
def find_signature_dict(pdf_path: str):
    reader = PdfReader(pdf_path)
    fields = reader.get_fields() or {}
    log(f"PDF fields found: {list(fields.keys())}")
    for pidx, page in enumerate(reader.pages):
        annots = page.get("/Annots")
        if not annots:
            continue
        for ref in annots:
            annot = ref.get_object()
            if annot.get("/Subtype") == "/Widget" and annot.get("/FT") == "/Sig":
                sig_ref = annot.get("/V")
                if sig_ref is None:
                    log(f"Signature field present on page {pidx+1} but empty (/V missing).")
                    continue
                sig = sig_ref.get_object()
                return {
                    "page": pidx+1,
                    "field_name": annot.get("/T"),
                    "sig_dict": sig,
                    "reader": reader
                }
    return None

# 2) Extract /Contents (PKCS#7) and /ByteRange
def extract_contents_and_byterange(sig_dict) -> Tuple[bytes, List[int]]:
    contents = sig_dict.get("/Contents")
    if contents is None:
        raise ValueError("No /Contents in signature dictionary")
    if isinstance(contents, (bytes, bytearray)):
        pkcs7 = bytes(contents)
    else:
        # try typical PyPDF2 access
        try:
            pkcs7 = contents.get_data()
        except Exception:
            pkcs7 = bytes(contents)
    br = sig_dict.get("/ByteRange")
    if not br or len(br) != 4:
        raise ValueError(f"Invalid /ByteRange: {br}")
    byterange = [int(x) for x in br]
    return pkcs7, byterange

def save_p7s(blob: bytes, out_path: str):
    with open(out_path, "wb") as f:
        f.write(blob)
    log(f"Saved PKCS#7 blob to {out_path} ({len(blob)} bytes)")

# 3) Compute hash over ByteRange
def compute_byterange_hash(pdf_path: str, byterange: List[int], hash_name="sha256") -> Tuple[bytes,str,bytes]:
    with open(pdf_path, "rb") as f:
        data = f.read()
    part1 = data[byterange[0] : byterange[0] + byterange[1]]
    part2 = data[byterange[2] : byterange[2] + byterange[3]]
    m = hashlib.new(hash_name)
    m.update(part1)
    m.update(part2)
    return m.digest(), m.hexdigest(), part1 + part2

# 4) Parse SignedData
def parse_signed_data(pkcs7_bytes: bytes):
    ci = cms.ContentInfo.load(pkcs7_bytes)
    if ci['content_type'].native != 'signed_data':
        raise ValueError("PKCS#7 content is not SignedData")
    sd = ci['content']
    signer_infos = sd['signer_infos']
    certs = sd['certificates']
    return sd, signer_infos, certs

# 5) Find signer cert and messageDigest
def find_signer_and_md(sd, signer_info):
    """
    Returns: (asn1_signer_cert or None, message_digest_bytes or None, signed_attrs or None)
    """
    # signed_attrs may be None
    signed_attrs = signer_info['signed_attrs'] if 'signed_attrs' in signer_info else None
    msg_digest = None
    if signed_attrs is not None:
        for attr in signed_attrs:
            # two ways: attr['type'].native == 'message_digest' or OID match
            try:
                if attr['type'].native == 'message_digest':
                    msg_digest = attr['values'][0].native
                    break
            except Exception:
                # fallback OID check
                if attr['type'].dotted == '1.2.840.113549.1.9.4':
                    msg_digest = attr['values'][0].native
                    break

    signer_cert_asn1 = None
    sid = signer_info['sid']
    # sid may be issuer_and_serial_number or subject_key_identifier
    # Try issuer_and_serial_number matching
    if sid.name == 'issuer_and_serial_number':
        wanted = sid.chosen
        for cert_choice in sd['certificates']:
            if cert_choice.name == 'certificate':
                cert = cert_choice.chosen  # asn1crypto.x509.Certificate
                try:
                    if hasattr(cert, 'issuer_serial') and cert.issuer_serial == wanted:
                        signer_cert_asn1 = cert
                        break
                except Exception:
                    continue
    else:
        # fallback: pick first certificate in list (common in many SignedData)
        for cert_choice in sd['certificates']:
            if cert_choice.name == 'certificate':
                signer_cert_asn1 = cert_choice.chosen
                break

    return signer_cert_asn1, msg_digest, signed_attrs

# Convert asn1 cert -> cryptography cert
def asn1_to_crypto_cert(asn1_cert):
    der = asn1_cert.dump()
    return x509.load_der_x509_certificate(der, backend=default_backend())

# 6) Verify signature over signedAttrs
def verify_signature_over_signed_attrs(crypto_cert: x509.Certificate, signer_info) -> Tuple[bool, str]:
    signature = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs'] if 'signed_attrs' in signer_info else None
    if signed_attrs is None:
        return False, "No signed_attrs present"
    signed_attrs_der = signed_attrs.dump()  # DER of SET OF attributes
    digest_alg = signer_info['digest_algorithm']['algorithm'].native
    if digest_alg not in ('sha1','sha256','sha384','sha512'):
        return False, f"Unsupported digest algorithm: {digest_alg}"
    hash_alg_map = {
        'sha1': hashes.SHA1(),
        'sha256': hashes.SHA256(),
        'sha384': hashes.SHA384(),
        'sha512': hashes.SHA512()
    }
    hash_alg = hash_alg_map[digest_alg]
    pubkey = crypto_cert.public_key()
    try:
        pubkey.verify(signature, signed_attrs_der, padding.PKCS1v15(), hash_alg)
        return True, f"Signature verified with PKCS#1 v1.5 and {digest_alg}"
    except Exception as e:
        return False, f"Signature verification error: {e}"

# 7) Build simple chain and check trust anchors
def build_chain_and_check_trust(certs_asn1, trust_paths: Optional[List[str]]):
    # convert list of CertificateChoices to cryptography certs
    cert_list = []
    for cc in certs_asn1:
        if cc.name == 'certificate':
            cert_list.append(asn1_to_crypto_cert(cc.chosen))
    if not cert_list:
        return [], False
    # greedy chain: pick candidate leaf whose subject not equal any issuer
    issuer_names = {c.issuer.rfc4514_string() for c in cert_list}
    leafs = [c for c in cert_list if c.subject.rfc4514_string() not in issuer_names]
    if not leafs:
        leafs = [cert_list[0]]
    chain = []
    cur = leafs[0]
    chain.append(cur)
    subj_map = {c.subject.rfc4514_string(): c for c in cert_list}
    while True:
        issuer_name = cur.issuer.rfc4514_string()
        if issuer_name == cur.subject.rfc4514_string():
            break
        nxt = subj_map.get(issuer_name)
        if not nxt:
            break
        if nxt == cur:
            break
        chain.append(nxt)
        cur = nxt
    # load trust anchors
    trusted_names = set()
    if trust_paths:
        for tp in trust_paths:
            try:
                with open(tp, "rb") as f:
                    data = f.read()
                try:
                    t = x509.load_pem_x509_certificate(data, backend=default_backend())
                except Exception:
                    t = x509.load_der_x509_certificate(data, backend=default_backend())
                trusted_names.add(t.subject.rfc4514_string())
            except Exception as e:
                log(f"Could not load trust anchor {tp}: {e}")
    trust_ok = False
    if chain:
        last = chain[-1]
        if last.subject.rfc4514_string() in trusted_names:
            trust_ok = True
    return chain, trust_ok

# 8) Attempt OCSP check (requires issuer certificate)
def attempt_ocsp(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except Exception:
        return "No AIA extension"
    ocsp_urls = []
    for desc in aia.value:
        if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(desc.access_location.value)
    if not ocsp_urls:
        return "No OCSP URL in AIA"
    if requests is None:
        return "requests not installed; cannot query OCSP"
    try:
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        req_data = req.public_bytes()
        headers = {"Content-Type": "application/ocsp-request"}
        for url in ocsp_urls:
            try:
                r = requests.post(url, data=req_data, headers=headers, timeout=8)
                if r.status_code == 200:
                    try:
                        ocsp_resp = load_der_ocsp_response(r.content)
                        return f"OCSP response status: {ocsp_resp.response_status}"
                    except Exception as e:
                        return f"OCSP response parse error: {e}"
                else:
                    return f"OCSP responder returned HTTP {r.status_code}"
            except Exception as e:
                log(f"OCSP query to {url} failed: {e}")
        return "OCSP queries failed"
    except Exception as e:
        return f"OCSP build/parse error: {e}"

# 9) Check timestamp token presence in unsigned_attrs
def has_timestamp_token(signer_info) -> Tuple[bool,str]:
    if 'unsigned_attrs' not in signer_info:
        return False, "No unsigned_attrs"
    ua = signer_info['unsigned_attrs']
    if ua is None:
        return False, "unsigned_attrs is empty"
    for attr in ua:
        # check both dotted OID and native name
        try:
            if attr['type'].native == 'signature_time_stamp_token':
                return True, "Found timestamp token (native)"
        except Exception:
            pass
        if attr['type'].dotted == '1.2.840.113549.1.9.16.2.14':
            return True, f"Found timestamp token (OID {attr['type'].dotted})"
    return False, "No timestamp token attribute found"

# 10) Check incremental update (extra data after ByteRange end)
def check_incremental(pdf_path: str, byterange: List[int]) -> Tuple[bool,str]:
    file_len = os.path.getsize(pdf_path)
    br_end = byterange[2] + byterange[3]
    extra = file_len - br_end
    if extra > 0:
        return False, f"Data exists after ByteRange end ({extra} bytes) — incremental updates/appended data present"
    return True, "No extra data after ByteRange end"

# Main orchestrator
def main(pdf_path: str, trust_paths: Optional[List[str]] = None):
    clear_log()
    log(f"=== BẮT ĐẦU XÁC THỰC CHỮ KÝ PDF: {pdf_path} ===")
    try:
        # Bước 1
        log("\n[Bước 1] Tìm signature dictionary (/Contents, /ByteRange)")
        info = find_signature_dict(pdf_path)
        if not info:
            log("❌ Không tìm thấy chữ ký trong PDF.")
            return
        sig_dict = info['sig_dict']
        log(f"✅ Tìm thấy chữ ký tại trang {info.get('page')} — field: {info.get('field_name')}")
        for k in ['/Contents','/ByteRange','/M','/Filter','/SubFilter']:
            if k in sig_dict:
                try:
                    log(f"  • {k}: {sig_dict.get(k)}")
                except Exception:
                    log(f"  • {k}: (unprintable)")

        # Bước 2
        log("\n[Bước 2] Trích xuất /Contents và /ByteRange")
        pkcs7_bytes, byterange = extract_contents_and_byterange(sig_dict)
        out_p7s = os.path.splitext(pdf_path)[0] + ".p7s"
        save_p7s(pkcs7_bytes, out_p7s)

        # Bước 3
        log("\n[Bước 3] Phân tích SignedData (PKCS#7)")
        sd, signer_infos, certs = parse_signed_data(pkcs7_bytes)
        log(f"  • SignedData version={sd['version'].native}, số signer_infos={len(signer_infos)}")

        signer_info = signer_infos[0]
        signer_cert_asn1, message_digest_attr, signed_attrs = find_signer_and_md(sd, signer_info)

        # Bước 4
        log("\n[Bước 4] Tìm certificate người ký & so sánh messageDigest")
        signer_cert_crypto = None
        if signer_cert_asn1 is None:
            log("❌ Không tìm thấy certificate trong SignedData.")
        else:
            signer_cert_crypto = asn1_to_crypto_cert(signer_cert_asn1)
            log(f"✅ Certificate: {signer_cert_crypto.subject.rfc4514_string()}")

        computed_digest, computed_hex, concat = compute_byterange_hash(pdf_path, byterange, hash_name='sha256')
        log(f"  • SHA-256 digest: {computed_hex}")
        if message_digest_attr is not None:
            log(f"  • messageDigest trong chữ ký: {binascii.hexlify(message_digest_attr).decode()}")
            if computed_digest == message_digest_attr:
                log("✅ messageDigest KHỚP với dữ liệu PDF — toàn vẹn OK")
            else:
                log("❌ messageDigest KHÔNG khớp — có thể bị chỉnh sửa hoặc ByteRange sai")
        else:
            log("⚠️ Không có messageDigest trong signed attributes")

        # Bước 5
        log("\n[Bước 5] Kiểm tra chữ ký mật mã học (RSA verify)")
        if signer_cert_crypto is not None:
            ok, msg = verify_signature_over_signed_attrs(signer_cert_crypto, signer_info)
            log("✅ " + msg if ok else "❌ " + msg)

        # Bước 6
        log("\n[Bước 6] Kiểm tra chuỗi chứng thư & trust anchors")
        chain, trust_ok = build_chain_and_check_trust(certs, trust_paths)
        log(f"  • Độ dài chuỗi chứng thư: {len(chain)}")
        for i, c in enumerate(chain):
            log(f"    [{i}] subject={c.subject.rfc4514_string()} issuer={c.issuer.rfc4514_string()}")
        if trust_paths:
            log(f"  • Trust anchors: {trust_paths} — Kết quả: {'OK' if trust_ok else 'Không khớp'}")
        else:
            log("  ⚠️ Không cung cấp trust anchor — không thể xác thực đến root CA")

        # Bước 7
        log("\n[Bước 7] Kiểm tra timestamp token (RFC3161)")
        ts_present, ts_msg = has_timestamp_token(signer_info)
        log(f"  • {ts_msg}")

        # Bước 8
        log("\n[Bước 8] Phát hiện incremental update (thêm dữ liệu sau ByteRange)")
        inc_ok, inc_msg = check_incremental(pdf_path, byterange)
        log(f"  • {inc_msg}")

        log("\n=== HOÀN TẤT XÁC THỰC PDF ===")
    except Exception as e:
        log(f"❌ Lỗi không mong đợi: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test.py signed.pdf [trust_anchor1.pem trust_anchor2.pem ...]")
        sys.exit(1)
    pdf_path = sys.argv[1]
    trust_list = sys.argv[2:] if len(sys.argv) > 2 else None
    main(pdf_path, trust_paths=trust_list)
