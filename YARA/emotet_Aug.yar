rule emotetMalDoc {
    meta:
        author = "Mert Degirmenci"
        description = "YARA rule to detect Emotet samples that trigger PS from VBA"
        date = "24.08.2020"
        hash1 = "2772a21e89149454d90094ecfabf3c087c5244211ecd89c353cdbdd276b35045"
        hash2 = "56d9c52e802a9a113f34157df47e580276b9c6ebbc14eeb39f041edb086e222b"
        hash3 = "29fb9ef0763b8010d5d4cc30ff3e5036c54a80fabf6c43d67ec65fe2a9f77fec"
        hash4 = "c9c3449c20e6ffd4b00908b514c5e5f0e3fc54d758023b96409fabe1152f643c"
        hash5 = "4f8bff007eeb2ac3b68400127782b5f65da36302d8e930bb6e51ecf2dde6137b"

    strings:
        //$magic = { d0 cf 11 e0 a1 b1 1a e1 }
        $s_vba = "_VBA_PROJECT" wide
        //$s_vbeDll = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applications" wide
        $s_version = "{C62A69F0-16DC-11CE-9E98-00AA00574A4F}" ascii
        $s_path = { 43 3a 5c 55 73 65 72 73 5c 41 44 4d 49 4e 49 7e 31 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 56 42 45 5c 4d 53 46 6f 72 6d 73 2e 65 78 64 0a }

    condition:
        // $magic at 0
        // and
        all of ($s_*)
        and
        filesize > 100KB and filesize < 700KB
}