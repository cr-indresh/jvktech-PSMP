"""
Seed the PoC with a realistic, FTSD-spec-exact dataset:

    python manage.py seed_demo

Creates:
* the 13 publication categories from the FTSD 3.1 service master
  (ABDC, Scopus Guaranteed/Non-Guaranteed, Web of Science, patents,
  copyrights, IEEE, Textbook) with base prices + provisioned author slots
* 4 users across all three roles
* 16 projects covering ALL SEVEN lifecycle stages (Draft -> ... ->
  Withdrawn) with full author profile data (FTSD 3.2) and payment logs
  carrying mode / date / remarks + Pending / Verified / Rejected states
* sample transaction-proof PNGs and acceptance-letter PNGs (rendered with
  a tiny built-in pixel font, pure stdlib -- no Pillow dependency)
"""

import struct
import zlib
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.utils import timezone

from tracker.models import (
    Author,
    PaymentInstallment,
    PaymentMode,
    PaymentType,
    Project,
    PublicationStatus,
    Role,
    ServiceType,
    UserProfile,
    VerificationStatus,
)

# ---------------------------------------------------------------------------
# FTSD 3.1 -- the service master (name, description, base price INR,
# provisioned author slots: 1 for books / full titles, 4-8 for patents
# and journal papers).
# ---------------------------------------------------------------------------
SERVICES = [
    ('ABDC', 'ABDC-listed journal publication', 45000, 6),
    ('Scopus Guaranteed', 'Guaranteed Scopus-indexed journal publication', 90000, 6),
    ('Scopus Non-Guaranteed', 'Best-effort Scopus-indexed journal publication', 55000, 6),
    ('Web of Science', 'Web of Science indexed publication', 75000, 6),
    ('Indian Design Patent', 'Indian design patent filing (IP office)', 60000, 5),
    ('UK Design Patent', 'UKIPO design patent filing', 120000, 5),
    ('German Patent', 'DPMA patent filing', 140000, 5),
    ('USA Patent', 'USPTO design / utility patent filing', 180000, 5),
    ('Indian Utility Patent', 'Indian utility patent filing', 65000, 5),
    ('Canadian Copyright', 'Canadian copyright registration', 40000, 4),
    ('Indian Copyright', 'Indian copyright registration', 25000, 4),
    ('IEEE', 'IEEE conference / journal publication', 70000, 6),
    ('Textbook', 'Full textbook / full-title publication', 150000, 1),
]

USERS = [
    # username, password, role, first, last, is_superuser
    ('admin', 'Admin@123', Role.ADMIN, 'System', 'Admin', True),
    ('bde.priya', 'Demo@123', Role.BDE, 'Priya', 'Sharma', False),
    ('bde.arjun', 'Demo@123', Role.BDE, 'Arjun', 'Mehta', False),
    ('acc.meera', 'Demo@123', Role.ACCOUNTS, 'Meera', 'Krishnan', False),
]

AUTHOR_POOL = [
    'Dr. Rakesh Sharma', 'Prof. Meera Iyer', 'Dr. A. K. Verma', 'Ms. Sneha Patil',
    'Dr. K. Ravindran', 'Mr. Aditya Rao', 'Dr. Anita Deshpande', 'Prof. S. Balakrishnan',
    'Dr. Farhan Qureshi', 'Ms. Divya Nair', 'Dr. Rohit Kulkarni', 'Prof. Nandini Rao',
    'Dr. Vikram Chauhan', 'Dr. Shalini Gupta', 'Mr. Karthik Subramanian',
]

# FTSD 3.2 author profile data (cycled across the seeded authors).
PROFILE_POOL = [
    {'designation': 'Professor', 'department': 'Computer Science',
     'company_name': 'Anna University', 'city': 'Chennai', 'district': 'Chennai',
     'state': 'Tamil Nadu', 'country': 'India', 'pin_code': '600025',
     'nationality': 'Indian',
     'full_address': 'Dept. of Computer Science, Anna University, Sardar Patel Road, Chennai 600025'},
    {'designation': 'Associate Professor', 'department': 'IT Consulting',
     'company_name': 'VIT University', 'city': 'Vellore', 'district': 'Vellore',
     'state': 'Tamil Nadu', 'country': 'India', 'pin_code': '632014',
     'nationality': 'Indian',
     'full_address': 'SCOPE Block, VIT University, Katpadi Road, Vellore 632014'},
    {'designation': 'Assistant Professor', 'department': 'Electronics Engineering',
     'company_name': 'IIT Madras', 'city': 'Chennai', 'district': 'Chennai',
     'state': 'Tamil Nadu', 'country': 'India', 'pin_code': '600036',
     'nationality': 'Indian',
     'full_address': 'EE Block 2, IIT Madras, Sardar Patel Road, Chennai 600036'},
    {'designation': 'Sr Data Engineer Architect', 'department': 'Data & Analytics',
     'company_name': 'TCS Research', 'city': 'Pune', 'district': 'Pune',
     'state': 'Maharashtra', 'country': 'India', 'pin_code': '411019',
     'nationality': 'Indian',
     'full_address': 'TCS Research, Rajashree Shahu Colony, Pune 411019'},
    {'designation': 'Research Scholar', 'department': 'Biotechnology',
     'company_name': 'Delhi Technological University', 'city': 'New Delhi',
     'district': 'North West Delhi', 'state': 'Delhi', 'country': 'India',
     'pin_code': '110042', 'nationality': 'Indian',
     'full_address': 'Biotech Block, DTU, Shahbad Daulatpur, New Delhi 110042'},
    {'designation': 'Industry Consultant', 'department': 'IT Consulting',
     'company_name': 'Infosys Labs', 'city': 'Bengaluru', 'district': 'Bengaluru Urban',
     'state': 'Karnataka', 'country': 'India', 'pin_code': '560100',
     'nationality': 'Indian',
     'full_address': 'Infosys Labs, EC Phase 1, Bengaluru 560100'},
]

DETAILS = [
    'Professor, Dept. of Computer Science, 15+ years of teaching experience.',
    'Associate Professor, AI & ML research group; ORCID 0000-0002-1825-0097.',
    'Research scholar; corresponding author for all communications.',
    'Industry consultant, co-author for applied chapters.',
    'Post-doctoral fellow; literature review and data curation lead.',
    '',
]


def author_contact(name, position):
    """
    Synthesize a demo email + phone for a seeded author from their name
    (deterministic so re-seeding produces stable data).
    """
    clean = (name.lower()
             .replace('dr. ', '').replace('prof. ', '')
             .replace('mr. ', '').replace('ms. ', '')
             .replace('.', '').replace(',', '').strip())
    parts = clean.split()
    if len(parts) >= 2:
        local = parts[-1] + '.' + ''.join(p[0] for p in parts[:-1])
    else:
        local = parts[0] if parts else 'author'
    phone = '+91 9' + f'{(position * 7654321) % 1000000000:09d}'
    return f'{local}@university.edu', phone


# title, service, bde, sale, discount, lifecycle status, acc_link, pub_link,
# acc_proof, [(payment_type, amount, txn, vstate, mode, day_offset, remarks)],
# author_count, days_ago
PROJECTS = [
    # ---- bde.priya ---------------------------------------------------------
    ('Machine Learning Applications in Agriculture — Textbook', 'Textbook', 'bde.priya',
     150000, 5000, 'COMPLETED', True, True, True,
     [('ADVANCE_1', 50000, 'UTR883729105', 'VERIFIED', 'UPI', 0, ''),
      ('ADVANCE_2', 45000, 'UTR883911402', 'VERIFIED', 'BANK_TRANSFER', 22, ''),
      ('REMAINING', 50000, 'UTR884220190', 'VERIFIED', 'UPI', 60, 'final settlement')], 1, 120),
    ('Federated Learning for IoT Security — Scopus Guaranteed Paper', 'Scopus Guaranteed', 'bde.priya',
     180000, 10000, 'ACCEPTED', True, False, True,
     [('ADVANCE_1', 60000, 'TXN-2025-00182', 'VERIFIED', 'UPI', 0, ''),
      ('ADVANCE_2', 40000, 'TXN-2025-00390', 'PENDING', 'UPI', 30, ''),
      ('REMAINING', 70000, None, 'PENDING', 'UPI', 0, '')], 6, 75),
    ('Explainable AI in Healthcare Diagnostics — ABDC Paper', 'ABDC', 'bde.priya',
     95000, 0, 'UNDER_REVIEW', False, False, False,
     [('ADVANCE_1', 30000, 'UTR883701566', 'PENDING', 'UPI', 2, '')], 5, 31),
    ('Blockchain for Supply Chain Traceability — IEEE Conference', 'IEEE', 'bde.priya',
     120000, 2000, 'SUBMITTED', False, False, False,
     [('ADVANCE_1', 40000, 'TXN-2025-00544', 'VERIFIED', 'BANK_TRANSFER', 1, ''),
      ('REMAINING', 78000, 'UTR883729105', 'REJECTED', 'UPI', 12,
       'client asked to re-check the reference')], 4, 22),
    ('Quantum Computing Foundations — Web of Science Chapter', 'Web of Science', 'bde.priya',
     110000, 0, 'DRAFT', False, False, False,
     [('ADVANCE_1', 35000, 'TXN-2025-00799', 'PENDING', 'UPI', 3, '')], 5, 7),
    ('Smart Antenna Design — Indian Design Patent', 'Indian Design Patent', 'bde.priya',
     60000, 0, 'ACCEPTED', True, False, True,
     [('ADVANCE_1', 20000, 'UPI-884100112', 'VERIFIED', 'UPI', 0, ''),
      ('ADVANCE_2', 20000, 'UPI-884110993', 'VERIFIED', 'UPI', 18, ''),
      ('REMAINING', 20000, None, 'PENDING', 'UPI', 0, '')], 5, 48),
    ('Low-Power IoT Sensor Circuit — Indian Utility Patent', 'Indian Utility Patent', 'bde.priya',
     65000, 3000, 'SUBMITTED', False, False, False,
     [('ADVANCE_1', 30000, 'TXN-2025-00821', 'VERIFIED', 'BANK_TRANSFER', 1, ''),
      ('REMAINING', 32000, None, 'PENDING', 'UPI', 0, '')], 4, 15),
    ('Tamil Folk Literature Corpus — Indian Copyright', 'Indian Copyright', 'bde.priya',
     25000, 0, 'COMPLETED', True, True, True,
     [('ADVANCE_1', 25000, 'UTR883977001', 'VERIFIED', 'UPI', 0, 'full settlement')], 4, 90),
    # ---- bde.arjun ---------------------------------------------------------
    ('Edge AI for Autonomous Drone Navigation — Scopus Non-Guaranteed Paper', 'Scopus Non-Guaranteed', 'bde.arjun',
     140000, 7500, 'SUBMITTED', False, False, False,
     [('ADVANCE_1', 50000, 'UTR883812090', 'PENDING', 'UPI', 4, '')], 6, 41),
    ('Wearable Health Monitoring Patch — USA Patent', 'USA Patent', 'bde.arjun',
     180000, 0, 'ACCEPTED', True, False, True,
     [('ADVANCE_1', 60000, 'TXN-2025-00261', 'VERIFIED', 'BANK_TRANSFER', 0, ''),
      ('ADVANCE_2', 60000, 'TXN-2025-00477', 'VERIFIED', 'BANK_TRANSFER', 25, ''),
      ('REMAINING', 60000, None, 'PENDING', 'UPI', 0, '')], 5, 65),
    ('NLP for Low-Resource Indian Languages — Scopus Guaranteed Paper', 'Scopus Guaranteed', 'bde.arjun',
     175000, 4000, 'PUBLISHED', True, True, True,
     [('ADVANCE_1', 60000, 'UTR883900744', 'VERIFIED', 'UPI', 0, ''),
      ('REMAINING', 111000, 'UTR884101256', 'VERIFIED', 'BANK_TRANSFER', 55, 'balance after DOI')], 6, 100),
    ('Drone Swarm Path Planning — IEEE Paper', 'IEEE', 'bde.arjun',
     130000, 8000, 'UNDER_REVIEW', False, False, False,
     [('ADVANCE_1', 45000, 'UTR883995501', 'PENDING', 'UPI', 5, '')], 4, 12),
    ('Cybersecurity Lab Manual — Textbook', 'Textbook', 'bde.arjun',
     75000, 2500, 'WITHDRAWN', False, False, False,
     [('ADVANCE_1', 25000, 'TXN-2025-00688', 'VERIFIED', 'UPI', 0, ''),
      ('ADVANCE_2', 25000, 'TXN-2025-00756', 'REJECTED', 'UPI', 20,
       'client paused the project — payment bounced')], 1, 50),
    ('Ergonomic Chair Ornament — Canadian Copyright', 'Canadian Copyright', 'bde.arjun',
     40000, 0, 'SUBMITTED', False, False, False,
     [('ADVANCE_1', 15000, 'TXN-2025-00633', 'PENDING', 'BANK_TRANSFER', 2, '')], 4, 18),
    ('Smart Grid Optimisation Techniques — UK Design Patent', 'UK Design Patent', 'bde.arjun',
     120000, 0, 'DRAFT', False, False, False,
     [('ADVANCE_1', 40000, 'TXN-2025-00810', 'VERIFIED', 'BANK_TRANSFER', 1, ''),
      ('ADVANCE_2', 20000, 'UPI-884120077', 'PENDING', 'UPI', 4, '')], 5, 9),
    ('IIoT Gateway Enclosure — German Patent', 'German Patent', 'bde.arjun',
     140000, 6000, 'SUBMITTED', False, False, False,
     [('ADVANCE_1', 50000, 'UTR884220190', 'PENDING', 'BANK_TRANSFER', 3, ''),
      ('REMAINING', 84000, None, 'PENDING', 'UPI', 0, '')], 5, 26),
]


# ---------------------------------------------------------------------------
# Sample proof PNG renderer (pure stdlib -- no Pillow needed).  Draws a
# blocky receipt / acceptance letter with a 3x5 pixel font; intentionally
# simplistic so the Accounts proof-viewer has obvious sample data.
# ---------------------------------------------------------------------------
FONT_3X5 = {
    '0': ('111', '101', '101', '101', '111'),
    '1': ('010', '110', '010', '010', '111'),
    '2': ('111', '001', '111', '100', '111'),
    '3': ('111', '001', '111', '001', '111'),
    '4': ('101', '101', '111', '001', '001'),
    '5': ('111', '100', '111', '001', '111'),
    '6': ('111', '100', '111', '101', '111'),
    '7': ('111', '001', '001', '010', '010'),
    '8': ('111', '101', '111', '101', '111'),
    '9': ('111', '101', '111', '001', '111'),
    'A': ('111', '101', '111', '101', '101'),
    'B': ('110', '101', '110', '101', '110'),
    'C': ('111', '100', '100', '100', '111'),
    'D': ('110', '101', '101', '101', '110'),
    'E': ('111', '100', '111', '100', '111'),
    'F': ('111', '100', '111', '100', '100'),
    'G': ('111', '100', '101', '101', '111'),
    'H': ('101', '101', '111', '101', '101'),
    'I': ('111', '010', '010', '010', '111'),
    'K': ('101', '110', '100', '110', '101'),
    'L': ('100', '100', '100', '100', '111'),
    'M': ('101', '111', '111', '101', '101'),
    'N': ('110', '101', '101', '101', '101'),
    'O': ('111', '101', '101', '101', '111'),
    'P': ('111', '101', '111', '100', '100'),
    'R': ('111', '101', '111', '110', '101'),
    'S': ('111', '100', '111', '001', '111'),
    'T': ('111', '010', '010', '010', '010'),
    'U': ('101', '101', '101', '101', '111'),
    'V': ('101', '101', '101', '101', '010'),
    'W': ('101', '101', '111', '111', '101'),
    'X': ('101', '101', '010', '101', '101'),
    'Y': ('101', '101', '010', '010', '010'),
    'Z': ('111', '001', '010', '100', '111'),
    ' ': ('000', '000', '000', '000', '000'),
    '-': ('000', '000', '111', '000', '000'),
    ',': ('000', '000', '000', '010', '100'),
    '.': ('000', '000', '000', '000', '010'),
    ':': ('000', '010', '000', '010', '000'),
    '/': ('001', '001', '010', '100', '100'),
}

SLATE_DARK = (15, 23, 42)
SLATE_BODY = (51, 65, 85)
SLATE_SOFT = (100, 116, 139)
EMERALD = (5, 150, 105)
WHITE = (255, 255, 255)
BORDER = (226, 232, 240)


def _text_width(text, scale):
    return len(text) * 4 * scale - scale


def _draw_text(pixels, text, x, y, scale, color):
    """Stamp `text` into the pixel buffer at (x, y). Returns end x."""
    for ch in text.upper():
        glyph = FONT_3X5.get(ch, FONT_3X5[' '])
        for gy, row in enumerate(glyph):
            for gx, on in enumerate(row):
                if on != '1':
                    continue
                for sy in range(scale):
                    py = y + gy * scale + sy
                    if py < 0 or py >= len(pixels):
                        continue
                    for sx in range(scale):
                        px = x + gx * scale + sx
                        if 0 <= px < len(pixels[0]):
                            pixels[py][px] = color
        x += 4 * scale
    return x


def _png_chunk(tag, data):
    return (struct.pack('>I', len(data)) + tag + data
            + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF))


def _encode_png(pixels):
    height = len(pixels)
    width = len(pixels[0])
    raw = b''.join(
        b'\x00' + bytes(v for px in row for v in px) for row in pixels
    )
    return (
        b'\x89PNG\r\n\x1a\n'
        + _png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b'IDAT', zlib.compress(raw, 9))
        + _png_chunk(b'IEND', b'')
    )


def make_proof_png(payment_type, amount, txn_ref):
    """Render a 640px-wide sample payment receipt PNG for one installment."""
    width = 640
    band_h = 56
    pad = 30
    line_scale = 3
    line_step = 5 * line_scale + 18
    lines = [
        ('AMOUNT : RS ' + f'{int(amount):,}', SLATE_BODY),
        ('TXN REF : ' + str(txn_ref), SLATE_BODY),
        ('PAYMENT : ' + payment_type.replace('_', ' '), SLATE_SOFT),
        ('BENEFICIARY : JVK TECHNOLOGIES PVT LTD', SLATE_SOFT),
        ('STATUS : SUCCESS', EMERALD),
    ]
    divider_gap = 14
    bottom_h = 44
    height = (band_h + pad + len(lines) * line_step + divider_gap * 2 + 2
              + bottom_h)

    pixels = [[WHITE for _ in range(width)] for _ in range(height)]
    for y in range(band_h):
        pixels[y] = [SLATE_DARK] * width
    for y in range(height - bottom_h, height):
        pixels[y] = [EMERALD] * width

    header = 'PAYMENT RECEIPT'
    _draw_text(pixels, header,
               (width - _text_width(header, 4)) // 2,
               (band_h - 5 * 4) // 2, 4, WHITE)

    y = band_h + pad
    for text, color in lines:
        _draw_text(pixels, text, (width - _text_width(text, line_scale)) // 2,
                   y, line_scale, color)
        y += line_step

    for py in range(y + divider_gap, y + divider_gap + 2):
        for px in range(48, width - 48):
            pixels[py][px] = BORDER

    footer = 'JVK TECHNOLOGIES - SAMPLE PROOF'
    _draw_text(pixels, footer,
               (width - _text_width(footer, 2)) // 2,
               height - bottom_h + (bottom_h - 5 * 2) // 2, 2, WHITE)
    return _encode_png(pixels)


def make_acceptance_png(title):
    """Render a sample acceptance-letter PNG for an accepted project."""
    width = 640
    band_h = 56
    pad = 30
    line_scale = 2
    line_step = 5 * line_scale + 16
    # Title may exceed the pixel font -- wrap to short chunks of 34 chars.
    words = title.upper().replace('—', '-').split()
    rows, current = [], ''
    for word in words:
        candidate = (current + ' ' + word).strip()
        if len(candidate) > 34:
            rows.append(current)
            current = word
        else:
            current = candidate
    if current:
        rows.append(current)
    rows = rows[:6]

    lines = [('MANUSCRIPT ID : JVK-' + str(abs(hash(title)) % 9000 + 1000), SLATE_BODY)]
    lines += [(row, SLATE_SOFT) for row in rows]
    lines += [('DECISION : ACCEPTED FOR PUBLICATION', EMERALD)]

    divider_gap = 14
    bottom_h = 44
    height = (band_h + pad + len(lines) * line_step + divider_gap * 2 + 2
              + bottom_h)

    pixels = [[WHITE for _ in range(width)] for _ in range(height)]
    for y in range(band_h):
        pixels[y] = [SLATE_DARK] * width
    for y in range(height - bottom_h, height):
        pixels[y] = [EMERALD] * width

    header = 'ACCEPTANCE LETTER'
    _draw_text(pixels, header,
               (width - _text_width(header, 4)) // 2,
               (band_h - 5 * 4) // 2, 4, WHITE)

    y = band_h + pad
    for text, color in lines:
        _draw_text(pixels, text, 48, y, line_scale, color)
        y += line_step

    for py in range(y + divider_gap, y + divider_gap + 2):
        for px in range(48, width - 48):
            pixels[py][px] = BORDER

    footer = 'EDITORIAL OFFICE - SAMPLE PROOF'
    _draw_text(pixels, footer,
               (width - _text_width(footer, 2)) // 2,
               height - bottom_h + (bottom_h - 5 * 2) // 2, 2, WHITE)
    return _encode_png(pixels)


def attach_sample_proofs(stdout=None):
    """
    Attach a sample receipt PNG to every installment that has a real
    transaction reference but no proof yet.  Idempotent -- installments
    that already carry a proof (e.g. BDE uploads) are never touched.
    """
    created = 0
    targets = (PaymentInstallment.objects.filter(proof_image='')
               .exclude(transaction_ref__startswith='PENDING-')
               .order_by('id'))
    for inst in targets:
        png = make_proof_png(inst.payment_type, inst.amount_paid, inst.transaction_ref)
        fname = f'proof-{str(inst.transaction_ref).lower()[:40]}.png'
        inst.proof_image.save(fname, ContentFile(png), save=False)
        inst.save(update_fields=['proof_image'])
        created += 1
    if stdout and created:
        stdout.write(f'  Proofs    : {created} sample receipt image(s) attached')
    return created


class Command(BaseCommand):
    help = ('Seed demo service catalogue, users, projects, authors, '
            'payments, proofs and acceptance letters.')

    def handle(self, *args, **options):
        self.stdout.write('Seeding demo data ...')

        # ---- service catalogue (FTSD 3.1) --------------------------------
        services = {}
        for name, description, base_price, default_slots in SERVICES:
            service, _ = ServiceType.objects.update_or_create(
                name=name,
                defaults={
                    'description': description,
                    'base_price': Decimal(str(base_price)),
                    'default_slots': default_slots,
                    'is_active': True,
                },
            )
            services[name] = service

        # ---- users & roles ------------------------------------------------
        users = {}
        for username, password, role, first, last, is_superuser in USERS:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={'first_name': first, 'last_name': last, 'is_superuser': is_superuser,
                          'is_staff': is_superuser},
            )
            if created:
                user.set_password(password)
                user.save()
            # Signal creates the profile; enforce the intended role explicitly.
            UserProfile.objects.update_or_create(user=user, defaults={'role': role})
            users[username] = user
        accounts_verifier = users['acc.meera']

        # ---- projects -----------------------------------------------------
        author_offset = 0
        for (title, service_name, bde_username, sale, discount, status,
             has_acc_link, has_pub_link, has_acc_proof, installments,
             author_count, days_ago) in PROJECTS:

            service = services[service_name]
            project, created = Project.objects.get_or_create(
                title=title,
                defaults={
                    'service_type': service,
                    'bde': users[bde_username],
                    'sale_value': Decimal(str(sale)),
                    'discount_value': Decimal(str(discount)),
                    'total_slots': service.default_slots,
                    'publication_status': status,
                    'acceptance_link': (
                        'https://journal.example.com/acceptance/'
                        + title.lower().replace(' ', '-')[:40]
                    ) if has_acc_link else '',
                    'publication_url': (
                        'https://doi.org/10.1000/demo.' + str(abs(hash(title)) % 9000 + 1000)
                    ) if has_pub_link else '',
                },
            )
            if not created:
                continue

            created_at = timezone.now() - timedelta(days=days_ago)
            Project.objects.filter(pk=project.pk).update(created_at=created_at)

            # acceptance proof (FTSD 3.4) for accepted / published projects
            if has_acc_proof:
                png = make_acceptance_png(title)
                project.acceptance_file.save(
                    'acceptance-' + title.lower().replace(' ', '-')[:40] + '.png',
                    ContentFile(png), save=False,
                )
                Project.objects.filter(pk=project.pk).update(
                    acceptance_file=project.acceptance_file,
                )

            # author slot bookings (positions 1..N, capped by the service)
            for position in range(1, author_count + 1):
                author_name = AUTHOR_POOL[(author_offset + position) % len(AUTHOR_POOL)]
                author_email, author_phone = author_contact(author_name, author_offset + position)
                profile = PROFILE_POOL[(author_offset + position) % len(PROFILE_POOL)]
                Author.objects.create(
                    project=project,
                    name=author_name,
                    position=position,
                    details=DETAILS[(author_offset + position) % len(DETAILS)],
                    email=author_email,
                    phone=author_phone,
                    **profile,
                )
            author_offset += author_count

            # payment installment log (FTSD 3.3) -- authors pay
            # individually, so every installment names its paying author
            # (round-robin over the booked slots).
            project_authors = list(project.authors.all())
            for idx, (ptype, amount, txn, vstate, mode, day_offset, remarks) in enumerate(installments):
                installment = PaymentInstallment.objects.create(
                    project=project,
                    author=project_authors[idx % len(project_authors)],
                    payment_type=ptype,
                    installment_number=idx + 1,
                    amount_paid=Decimal(str(amount)),
                    transaction_ref=txn or f'PENDING-{project.pk}-{idx + 1}',
                    payment_mode=mode,
                    payment_date=(created_at + timedelta(days=day_offset)).date(),
                    remarks=remarks,
                    submitted_by=users[bde_username],
                    verification_status=vstate,
                    verified_by=accounts_verifier if vstate != 'PENDING' else None,
                    verification_date=(
                        created_at + timedelta(days=day_offset + 1)
                    ) if vstate != 'PENDING' else None,
                )
                PaymentInstallment.objects.filter(pk=installment.pk).update(
                    submitted_at=created_at + timedelta(hours=idx * 4),
                )

        # ---- sample proof photos (idempotent) -----------------------------
        attach_sample_proofs(self.stdout)

        self.stdout.write(self.style.SUCCESS('Seed complete.'))
        self.stdout.write('  Users     : ' + ', '.join(u[0] for u in USERS))
        self.stdout.write(f'  Services  : {ServiceType.objects.count()} (FTSD 3.1 catalogue)')
        self.stdout.write(f'  Projects  : {Project.objects.count()} '
                          f'(lifecycle stages covered: '
                          + ', '.join(
                              [s for s in PublicationStatus.values
                               if Project.objects.filter(publication_status=s).exists()]
                          ) + ')')
        self.stdout.write(f'  Authors   : {Author.objects.count()}')
        self.stdout.write(f'  Payments  : {PaymentInstallment.objects.count()} '
                          f'({PaymentInstallment.objects.filter(verification_status="VERIFIED").count()} verified, '
                          f'{PaymentInstallment.objects.filter(verification_status="REJECTED").count()} rejected)')
        self.stdout.write(f'  Proofs    : {PaymentInstallment.objects.exclude(proof_image="").count()} '
                          f'photo(s) attached')
