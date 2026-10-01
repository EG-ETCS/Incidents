# Apple CoreGraphics Zero-Day - CVE-2026-86950
![alt text](images/CoreGraphics.png)

**Apple**{.cve-chip} **CoreGraphics**{.cve-chip} **CVE-2026-86950**{.cve-chip} **Out-of-Bounds Write**{.cve-chip} **Zero-Day**{.cve-chip}

## Overview

Apple patched CVE-2026-86950, an out-of-bounds write vulnerability in CoreGraphics. CoreGraphics is responsible for graphics, text rendering, and PDF processing across Apple platforms.

Apple attributed the report to Meta Product Security and stated the vulnerability may have been exploited in an extremely sophisticated attack against specific targeted individuals running iOS versions before iOS 27.

Researchers later published a public PoC showing that a specially crafted PDF with a maliciously constructed font can trigger the memory-corruption condition.

The same research also identified new WhatsApp PDF/font security checks, creating a possible connection between WhatsApp and the vulnerability. However, there is no public confirmation that WhatsApp was the actual delivery mechanism in real-world attacks.

## Technical Details

The vulnerability exists in CoreGraphics path-rasterization code.

Publicly analyzed exploit path:

1. A malicious PDF contains a specially crafted TrueType font.
2. The font uses carefully selected glyph coordinates.
3. PDF text transformations and nested composite-glyph scaling produce unusually large coordinates.
4. CoreGraphics converts floating-point coordinates into fixed-point values.
5. An integer/coordinate conversion issue causes an incorrect bounding-box calculation.
6. CoreGraphics allocates an undersized rendering buffer.
7. Glyph rendering writes outside the allocated buffer.
8. This results in an out-of-bounds write and memory corruption.

The public PoC demonstrates memory corruption on iOS and macOS, but it does not provide a complete working remote-code-execution exploit. Converting this primitive into reliable code execution would require additional exploitation work.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **CVE** | CVE-2026-86950 |
| **Component** | Apple CoreGraphics (graphics/text/PDF processing) |
| **Vulnerability Type** | Out-of-bounds write (memory corruption) |
| **Trigger Artifact** | Specially crafted PDF with malicious TrueType font data |
| **Exploit Primitive** | Bounding-box miscalculation leading to undersized buffer allocation |
| **Known Exploitation Context** | Apple reported possible targeted in-the-wild abuse prior to iOS 27 |

## Affected Products

- iOS and iPadOS devices processing malicious PDFs.
- macOS systems processing malicious PDFs in vulnerable versions.
- Any application workflow that invokes CoreGraphics PDF/font rendering on unpatched Apple platforms.

## Attack Scenario

1. Attacker creates a specially crafted malicious PDF.
2. The PDF embeds a maliciously constructed TrueType font.
3. The attacker delivers the file through possible channels such as messaging apps, email attachments, web content, or other PDF-processing apps.
4. The target device processes or previews the PDF.
5. CoreGraphics parses the embedded font and renders glyphs.
6. Crafted coordinates trigger coordinate-conversion flaws and an incorrect glyph bounding box.
7. An undersized memory buffer is allocated.
8. Glyph rendering writes beyond the allocated buffer, causing memory corruption.
9. The memory-corruption primitive could potentially be developed into arbitrary code execution.

## Impact Assessment

=== "Primary Impact"

    - Potential remote code execution through malicious file processing
    - Memory corruption and application crashes
    - Potential compromise of targeted iPhones and iPads

=== "Secondary Risk"

    - Possible access to application or device data when chained with additional vulnerabilities
    - Elevated risk for high-value targets such as executives, researchers, journalists, and government personnel
    - Public PoC lowers the barrier for reproducing core vulnerability behavior

=== "Severity Context"

    - Apple indicated the issue may lead to arbitrary code execution and may have been used in an extremely sophisticated targeted attack

## Mitigation Strategies

### 1) Patch Apple devices immediately

Apply relevant updates:

- iOS 26.7.1
- iPadOS 26.7.1
- macOS Tahoe 26.7.1
- macOS Sequoia 15.8.1

Apple advisories indicate the flaw was addressed through improved bounds checking.

### 2) Prioritize high-value targeted devices

Because Apple reported possible targeted exploitation, organizations should prioritize updates for executives, security teams, administrators, and other high-value users.

### 3) Avoid opening unexpected PDFs until patching is complete

Users should avoid opening suspicious PDFs or documents received through messaging applications, email, or unknown websites.

### 4) Maintain application updates

Messaging applications such as WhatsApp should remain updated because attachment-processing hardening can provide an additional defensive layer.

## Resources and References

!!! info "Public Reporting"
    - [Apple CoreGraphics PoC Emerges as WhatsApp PDF Checks Hint at Possible Delivery Path](https://thehackernews.com/2026/10/apple-coregraphics-poc-emerges-as.html)
    - [Apple Patches Zero-Day Linked to 'Extremely Sophisticated Attack' - SecurityWeek](https://www.securityweek.com/apple-patches-meta-reported-zero-day-linked-to-extremely-sophisticated-attack/)
    - [CVE-2026-86950: The Great Glyph Grift | Calif](https://calif.io/research/the-great-glyph-grift)

---

*Last Updated: October 1, 2026*
