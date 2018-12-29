rule WindowsScriptEncoderFiletype {
    meta:
        author = "github.com/sstraw"
        source = "github.com/sstraw/scrdec"
        description = "Detects Windows Script Encoder payloads"

    strings:
        $header = /\#\@\~\^[a-zA-Z0-9+\/=]{8}/ ascii wide
        $footer = /[a-zA-Z0-9+\/=]{8}\^\#\~\@/ ascii wide

    condition:
        all of them
}
