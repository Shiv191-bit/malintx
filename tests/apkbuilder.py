"""Test-only builder for *synthetic* APK fixtures.

Produces structurally valid binary AndroidManifest.xml (AXML), DEX and a signed ZIP container
from a declarative spec. The resulting files are inert: DEX methods only contain invoke
instructions referencing framework APIs, so they can be parsed but are not meaningful programs.
They are NOT malware samples and say nothing about real-world detection performance.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# --------------------------------------------------------------------------- AXML
@dataclass
class El:
    tag: str
    attrs: dict[str, object] = field(default_factory=dict)
    children: list[El] = field(default_factory=list)


def build_axml(root: El) -> bytes:
    strings: list[str] = []

    def sidx(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    ns_uri = sidx(ANDROID_NS)
    ns_prefix = sidx("android")

    body = io.BytesIO()
    NONE = 0xFFFFFFFF
    line = [1]

    def emit(el: El) -> None:
        name = sidx(el.tag)
        attrs = []
        for key, val in el.attrs.items():
            ns = NONE
            local = key
            if key.startswith("android:"):
                ns = ns_uri
                local = key.split(":", 1)[1]
            a_name = sidx(local)
            if isinstance(val, bool):
                raw, dtype, data = NONE, 0x12, 0xFFFFFFFF if val else 0
            elif isinstance(val, int):
                raw, dtype, data = NONE, 0x10, val & 0xFFFFFFFF
            else:
                s = sidx(str(val))
                raw, dtype, data = s, 0x03, s
            attrs.append((ns, a_name, raw, dtype, data))
        payload = struct.pack("<II", line[0], NONE)
        payload += struct.pack("<II", NONE, name)
        payload += struct.pack("<HHHHHH", 0x14, 0x14, len(attrs), 0, 0, 0)
        for ns, a_name, raw, dtype, data in attrs:
            payload += struct.pack("<III", ns, a_name, raw)
            payload += struct.pack("<HBBI", 8, 0, dtype, data)
        body.write(struct.pack("<HHI", 0x0102, 16, 16 + len(payload) - 8) + payload)
        line[0] += 1
        for child in el.children:
            emit(child)
        end = struct.pack("<II", line[0], NONE) + struct.pack("<II", NONE, name)
        body.write(struct.pack("<HHI", 0x0103, 16, 16 + len(end) - 8) + end)
        line[0] += 1

    # namespace start
    ns_payload = struct.pack("<IIII", 1, NONE, ns_prefix, ns_uri)
    body.write(struct.pack("<HHI", 0x0100, 16, 16 + len(ns_payload) - 8) + ns_payload)
    emit(root)
    ns_end = struct.pack("<IIII", line[0], NONE, ns_prefix, ns_uri)
    body.write(struct.pack("<HHI", 0x0101, 16, 16 + len(ns_end) - 8) + ns_end)

    # string pool (UTF-16)
    offsets, data = [], io.BytesIO()
    for s in strings:
        offsets.append(data.tell())
        data.write(struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00")
    pool_data = data.getvalue()
    if len(pool_data) % 4:
        pool_data += b"\x00" * (4 - len(pool_data) % 4)
    strings_start = 28 + 4 * len(strings)
    pool_payload = struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
    pool_payload += b"".join(struct.pack("<I", o) for o in offsets) + pool_data
    pool = struct.pack("<HHI", 0x0001, 28, 8 + len(pool_payload)) + pool_payload

    inner = pool + body.getvalue()
    return struct.pack("<HHI", 0x0003, 8, 8 + len(inner)) + inner


# --------------------------------------------------------------------------- DEX
@dataclass
class Call:
    owner: str  # e.g. Landroid/telephony/SmsManager;
    name: str
    ret: str = "V"
    params: tuple[str, ...] = ()
    kind: str = "virtual"  # virtual | static | direct | interface


@dataclass
class MethodSpec:
    name: str
    ret: str = "V"
    params: tuple[str, ...] = ()
    calls: list[Call] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)


@dataclass
class ClassSpec:
    name: str
    superclass: str = "Ljava/lang/Object;"
    methods: list[MethodSpec] = field(default_factory=list)


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _shorty(ret: str, params: tuple[str, ...]) -> str:
    def c(t: str) -> str:
        return "L" if t[0] in "L[" else t

    return c(ret) + "".join(c(p) for p in params)


def build_dex(classes: list[ClassSpec]) -> bytes:
    str_set: set[str] = set()
    type_set: set[str] = set()
    protos: set[tuple[str, tuple[str, ...]]] = set()
    methods: set[tuple[str, str, str, tuple[str, ...]]] = set()  # owner, name, ret, params

    def add_proto(ret: str, params: tuple[str, ...]) -> None:
        protos.add((ret, params))
        type_set.add(ret)
        type_set.update(params)
        str_set.add(_shorty(ret, params))

    for cls in classes:
        type_set.add(cls.name)
        type_set.add(cls.superclass)
        for m in cls.methods:
            add_proto(m.ret, m.params)
            methods.add((cls.name, m.name, m.ret, m.params))
            str_set.add(m.name)
            str_set.update(m.strings)
            for call in m.calls:
                add_proto(call.ret, call.params)
                methods.add((call.owner, call.name, call.ret, call.params))
                type_set.add(call.owner)
                str_set.add(call.name)
    str_set.update(type_set)

    strings = sorted(str_set, key=lambda s: s.encode("utf-8"))
    s_idx = {s: i for i, s in enumerate(strings)}
    types = sorted(type_set, key=lambda t: s_idx[t])
    t_idx = {t: i for i, t in enumerate(types)}
    proto_list = sorted(protos, key=lambda p: (t_idx[p[0]], [t_idx[x] for x in p[1]]))
    p_idx = {p: i for i, p in enumerate(proto_list)}
    method_list = sorted(
        methods, key=lambda m: (t_idx[m[0]], s_idx[m[1]], p_idx[(m[2], m[3])])
    )
    m_idx = {m: i for i, m in enumerate(method_list)}

    # order classes so that defined superclasses come first
    ordered: list[ClassSpec] = []
    pending = list(classes)
    defined = {c.name for c in classes}
    while pending:
        for c in list(pending):
            if c.superclass not in defined or any(o.name == c.superclass for o in ordered):
                ordered.append(c)
                pending.remove(c)
                break
        else:  # cycle: just append
            ordered.extend(pending)
            break

    header_size = 0x70
    n_str, n_type, n_proto, n_meth, n_cls = (
        len(strings), len(types), len(proto_list), len(method_list), len(ordered)
    )
    str_off = header_size
    type_off = str_off + 4 * n_str
    proto_off = type_off + 4 * n_type
    meth_off = proto_off + 12 * n_proto
    cls_off = meth_off + 8 * n_meth
    data_off = cls_off + 32 * n_cls

    data = bytearray()

    def align(n: int) -> None:
        while (data_off + len(data)) % n:
            data.append(0)

    # string data
    string_data_off = []
    string_section_start = data_off + len(data)
    for s in strings:
        string_data_off.append(data_off + len(data))
        data += _uleb(len(s)) + s.encode("utf-8") + b"\x00"

    # type lists
    type_list_off: dict[tuple[str, ...], int] = {}
    type_list_start = None
    for _, params in proto_list:
        if params and params not in type_list_off:
            align(4)
            if type_list_start is None:
                type_list_start = data_off + len(data)
            type_list_off[params] = data_off + len(data)
            data += struct.pack("<I", len(params)) + b"".join(
                struct.pack("<H", t_idx[p]) for p in params
            )
            if len(params) % 2:
                data += b"\x00\x00"

    # code items
    code_off: dict[tuple[str, str], int] = {}
    code_start = None
    for cls in ordered:
        for m in cls.methods:
            align(4)
            if code_start is None:
                code_start = data_off + len(data)
            code_off[(cls.name, m.name)] = data_off + len(data)
            insns: list[int] = []
            for k, text in enumerate(m.strings):
                insns += [((k % 8) << 8) | 0x1A, s_idx[text]]
            for call in m.calls:
                opcode = {"virtual": 0x6E, "direct": 0x70, "static": 0x71, "interface": 0x72}[call.kind]
                n_args = len(call.params) + (0 if call.kind == "static" else 1)
                n_args = min(n_args, 5)
                insns += [(n_args << 12) | opcode, m_idx[(call.owner, call.name, call.ret, call.params)], 0]
            insns.append(0x000E)  # return-void
            data += struct.pack("<HHHHII", 8, len(m.params) + 1, 5, 0, 0, len(insns))
            data += b"".join(struct.pack("<H", u) for u in insns)

    # class data
    class_data_off: dict[str, int] = {}
    class_data_start = None
    for cls in ordered:
        if not cls.methods:
            class_data_off[cls.name] = 0
            continue
        if class_data_start is None:
            class_data_start = data_off + len(data)
        class_data_off[cls.name] = data_off + len(data)
        entries = sorted(
            ((m_idx[(cls.name, m.name, m.ret, m.params)], m) for m in cls.methods), key=lambda e: e[0]
        )
        blob = _uleb(0) + _uleb(0) + _uleb(0) + _uleb(len(entries))
        prev = 0
        for idx, m in entries:
            blob += _uleb(idx - prev) + _uleb(0x1) + _uleb(code_off[(cls.name, m.name)])
            prev = idx
        data += blob

    # map list
    align(4)
    map_off = data_off + len(data)
    items = [
        (0x0000, 1, 0),
        (0x0001, n_str, str_off),
        (0x0002, n_type, type_off),
        (0x0003, n_proto, proto_off),
        (0x0005, n_meth, meth_off),
        (0x0006, n_cls, cls_off),
        (0x2002, n_str, string_section_start),
    ]
    if type_list_start is not None:
        items.append((0x1001, len(type_list_off), type_list_start))
    if code_start is not None:
        items.append((0x2001, len(code_off), code_start))
    if class_data_start is not None:
        items.append((0x2000, sum(1 for v in class_data_off.values() if v), class_data_start))
    items.append((0x1000, 1, map_off))
    items = [i for i in items if i[1] > 0]
    items.sort(key=lambda i: i[2])
    data += struct.pack("<I", len(items))
    for t, size, off in items:
        data += struct.pack("<HHII", t, 0, size, off)

    out = bytearray()
    for off in string_data_off:
        out += struct.pack("<I", off)
    for t in types:
        out += struct.pack("<I", s_idx[t])
    for ret, params in proto_list:
        out += struct.pack(
            "<III", s_idx[_shorty(ret, params)], t_idx[ret], type_list_off.get(params, 0)
        )
    for owner, name, ret, params in method_list:
        out += struct.pack("<HHI", t_idx[owner], p_idx[(ret, params)], s_idx[name])
    for cls in ordered:
        out += struct.pack(
            "<IIIIIIII",
            t_idx[cls.name], 1, t_idx[cls.superclass], 0, 0xFFFFFFFF, 0, class_data_off[cls.name], 0,
        )

    body = bytes(out) + bytes(data)
    file_size = header_size + len(body)
    hdr = bytearray(b"dex\n035\x00")
    hdr += b"\x00" * 4 + b"\x00" * 20  # checksum + signature placeholders
    hdr += struct.pack(
        "<IIIIIIIIIIIIIIIIII",
        file_size, header_size, 0x12345678, 0, 0, map_off,
        n_str, str_off, n_type, type_off, n_proto, proto_off,
        0, 0, n_meth, meth_off, n_cls, cls_off,
    )
    hdr += struct.pack("<II", file_size - data_off, data_off)
    assert len(hdr) == header_size, len(hdr)
    full = bytearray(hdr + body)
    full[12:32] = hashlib.sha1(bytes(full[32:])).digest()
    full[8:12] = struct.pack("<I", zlib.adler32(bytes(full[12:])) & 0xFFFFFFFF)
    return bytes(full)


# --------------------------------------------------------------------------- APK
def _self_signed_pkcs7(payload: bytes) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "MALINT-X Synthetic Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "malintx-tests"),
        ]
    )
    now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234567)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=9000))
        .sign(key, hashes.SHA256())
    )
    sig = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(payload)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )
    return sig, cert.public_bytes(serialization.Encoding.DER)


def build_apk(
    manifest: El,
    classes: list[ClassSpec] | None,
    *,
    sign: bool = True,
    raw_dex: bytes | None = None,
    extra_files: dict[str, bytes] | None = None,
    extra_dex: list[list[ClassSpec]] | None = None,
) -> bytes:
    buf = io.BytesIO()
    stamp = (2024, 1, 1, 0, 0, 0)

    def add(zf: zipfile.ZipFile, name: str, content: bytes) -> None:
        zi = zipfile.ZipInfo(name, date_time=stamp)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(zi, content)

    with zipfile.ZipFile(buf, "w") as zf:
        add(zf, "AndroidManifest.xml", build_axml(manifest))
        if raw_dex is not None:
            add(zf, "classes.dex", raw_dex)
        elif classes is not None:
            add(zf, "classes.dex", build_dex(classes))
        for i, extra in enumerate(extra_dex or [], start=2):
            add(zf, f"classes{i}.dex", build_dex(extra))
        for name, content in (extra_files or {}).items():
            add(zf, name, content)
        if sign:
            mf = b"Manifest-Version: 1.0\r\nCreated-By: malintx-tests\r\n\r\n"
            sf = b"Signature-Version: 1.0\r\nCreated-By: malintx-tests\r\n\r\n"
            sig, _ = _self_signed_pkcs7(sf)
            add(zf, "META-INF/MANIFEST.MF", mf)
            add(zf, "META-INF/CERT.SF", sf)
            add(zf, "META-INF/CERT.RSA", sig)
    return buf.getvalue()
