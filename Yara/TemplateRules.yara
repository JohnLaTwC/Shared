rule gen_injected_template_Word
{
    meta:
        description = "Detects injected templates in DOCX"
        author = "John Lambert @JohnLaTwC"
        date = "2020-05-03"
        hash1 = "a3eca35d14b0e020444186a5faaba5997994a47af08580521f808b1bb83d6063"
        hash2 = "a275dfa95393148bb9e0ddf5346f9fedcc9c87fa2ec3ce1ec875843664c37c89"
        hash3 = "ed4835e5fd10bbd2be04c5ea9eb2b8e750aff2ef235de6e0f18d369469f69c83"
        file_protocol_hash1 = "ac6c1df3895af63b864bb33bf30cb31059e247443ddb8f23517849362ec94f08 (settings.xml.rels)"
        reference1 = "https://twitter.com/Timele9527/status/1253941585026314240"
        reference2 = "https://blog.talosintelligence.com/2017/07/template-injection.html"
    strings:
        $header_xml = { 3c 3f 78 6d } 
        $header_xml_2 = { ef bb bf 3c 3f 78 6d } 
        $s1 = "Target=\"http"
        $s2 = /Target=\"file:\/\/\d/

        $r1 = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
        $r2a = "\"http://schemas.openxmlformats.org/package/2006/relationships\""
        $r2b = "<Relationships"
        $r2c = "TargetMode=\"External"

    condition:
        filesize < 3KB
        and ($header_xml at 0 or $header_xml_2 at 0 )
        and any of ($s*)
        and ($r1 or all of ($r2*))
}

rule gen_injected_template_Word_web
{
    meta:
        description = "Detects injected templates in DOCX"
        author = "John Lambert @JohnLaTwC"
        date = "2020-05-03"
        hash1 = "a3eca35d14b0e020444186a5faaba5997994a47af08580521f808b1bb83d6063"
        hash2 = "a275dfa95393148bb9e0ddf5346f9fedcc9c87fa2ec3ce1ec875843664c37c89"
        reference1 = "https://twitter.com/Timele9527/status/1253941585026314240"
        reference2 = "https://blog.talosintelligence.com/2017/07/template-injection.html"
    strings:
        $s1 = "Target=\"http"

    condition:
        gen_injected_template_Word
        and all of ($s*)
}

rule gen_injected_template_Word_DOTM_DOCM
{
    meta:
        description = "Detects injected templates in DOCX with DOTM/DOCM extension"
        author = "John Lambert @JohnLaTwC"
        date = "2020-05-03"
        hash1 = "a3eca35d14b0e020444186a5faaba5997994a47af08580521f808b1bb83d6063"
        reference1 = "https://twitter.com/Timele9527/status/1253941585026314240"
    strings:
        // .dotm" or .docm"
        $s3 = {2e 64 6f (74|63 ) 6d 22}

    condition:
        gen_injected_template_Word_web
        and $s3
}

rule gen_injected_template_Word_online_fileshare
{
    meta:
        description = "Detects injected templates in DOCX with DOTM/DOCM extension"
        author = "John Lambert @JohnLaTwC"
        date = "2020-05-03"
        hash1 = "a275dfa95393148bb9e0ddf5346f9fedcc9c87fa2ec3ce1ec875843664c37c89"
        reference1 = "https://twitter.com/Timele9527/status/1253941585026314240"
    strings:
        // .dotm" or .docm"
        $s3 = "https://drive.google.com/"
        $s4 = "https://onedrive"
        $s5 = "https://1drv.ms/"
        $s6 = "docs.live.net/"
        $s7 = "sharepoint.com"
        $s8 = "duckdns.org"
    condition:
        gen_injected_template_Word_web
        and 1 of ($s*)
}

rule gen_injected_template_Word_RTF
{
    meta:
        description = "Detects injected templates in DOCX with DOTM/DOCM extension"
        author = "John Lambert @JohnLaTwC"
        date = "2020-05-03"
        hash1 = "4f591b5db3401021d108368950e9c0c0ca638f50bba5da0c03986e7c137bec89"
    strings:
        $r1 = /Target="http:[\S]{3,80}[rtf|RTF]/
        $r2 = /Target="https:[\S]{3,80}[rtf|RTF]/
    condition:
        gen_injected_template_Word_web
        and any of ($r*)
}
