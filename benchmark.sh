#!/bin/bash -v

# check if cpk-1.0.tar.gz exist 
# install openssl
# install cpk and run cpk_test
# include cpktool 
# install cpkadm 
# install apache2
# install cgi scripts 


mkdir .cpktest 2&>1 > /dev/null
cd .cpktest

echo "create random data files"
dd bs=1000 count=1     skip=0 if=/dev/urandom of=1KB.bin 
dd bs=1000 count=1000  skip=0 if=/dev/urandom of=1MB.bin
dd bs=1000 count=10000 skip=0 if=/dev/urandom of=10MB.bin
ls -alh *.bin


cpk -set-identity alice@pku.edu.cn




time cpk -genkey alice@pku.edu.cn -pass password -out alice@pku.edu.cn.pem
time openssl genrsa 2048




cpk -import-sign-key    -in alice@pku.edu.cn.pem -pass password
cpk -import-decrypt-key -in alice@pku.edu.cn.pem -pass password

time echo helloworld | cpk -sign -pass $PASSWORD
time echo helloworld | cpk -sign -pass $PASSWORD

time cpk -sign -in 1KB.bin -pass password
time cpk -sign -in 1MB.bin -pass password
time cpk -sign -in 10MB.bin -pass password

time cpk -encrypt -in 1KB.bin  -to alice@pku.edu.cn -out 1KB.cpk
time cpk -encrypt -in 1MB.bin  -to alice@pku.edu.cn -out 1MB.cpk
time cpk -encrypt -in 10MB.bin -to alice@pku.edu.cn -out 10MB.cpk


# run cpk_test

GPG_PUBKEY="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.18 (Darwin)
Comment: GPGTools - http://gpgtools.org

mQENBFDeq+UBCADJj6VP7jMFPQUE7xjsMc/LrsQKwt6QLI1dinuEwbzvvnowtskv
2oV9Rr4TTv5Yw32G5GZz2oCd9iSw77nV5m7n1r2OURdoPDIk0PBgNLAIACUngvBc
ttOyXr0yezf0sGM0a0QSWSsSmou3NZ7FAyATqe9tvcetypSbZIaoldSufnWv1Hxn
H5NiXioNkkAhLTfTrcN0Jj4q1jwzvMM0VVquDnK/xFwKFJO6VR3RdKnRsLWUwCJV
v3ZSNMtzYeJH4XFo3BGD00doBQUDMnywZRtTa0x26I9MHnVx0MTEWI2GgN5wn19Z
a3X/sAPw5wpJmS0xh2m4h0/lLH0Yo5hJgV4dABEBAAG0G1poaSBHdWFuIDxndWFu
ekBwa3UuZWR1LmNuPokBOQQTAQIAIwUCUN6r5QIbAwcLCQgHAwIBBhUIAgkKCwQW
AgMBAh4BAheAAAoJELDEfMF3bkdvG5MH/11KtdzdGSJLL3rtN7pM5EdBKj0OAlUT
eQKX+EvpvG64zEBaofkHDZ7xQzeOI8v8Ll1fd4LGLaHpBmMsxghWP14ynCHiZ9ed
ueaehRO1WQE6Buk9nBWTeS705wXw87pmVlNX6igkKTIXZqLBXCcEmGPXZqs5VCjF
ZF2ZN1hYkwvxB5NV0gy5JzWGGRD3p2SJHLm1ZjAnJjwYvahg+jU2UhhtR3dY43+k
Zp+hRMRNoPrKhwEqVm4m1Aw2ZBFh/nlYxwMkQR0RN0nVCEO6hoMfFBeUtVk2f83o
Tjjak3wMKaGYC40hIsIFG515QaeyEGLndzm1E/jrG6dEHLNc+iNLr4O5AQ0EUN6r
5QEIAKZjyxo9nNeZM6yOB5KSFapMpP7Wq5uyySHFADbsdFOyuXeCYz9DgK4G3ZeJ
JiHvzkfZ2vYOfa+zwBw0amX+A5g9JZyfQJjGRcNn4UIQHGlJo30LIR5oq1ztlh5E
grmj9JzwmurhkPi4hIuYlX1RGSpm+eCZ8Idj5fjHNi+KUQ/Lx90AQRFsZsUODm5F
ZoAkWrT1Y2GvUWsyZ11aYBxBuXqJTF1UDdCeIEIDDfE7KgZUMLu+w1S2TyqkORHH
Dg0lukMMnq6Nsrrzvh/68zVeMzRQ8RASRrziWyPiu2DVyAuJ/TD3iEHQUDldWOd6
c/zP1D4FQ1hom+XPcmQDIt1twSMAEQEAAYkBHwQYAQIACQUCUN6r5QIbDAAKCRCw
xHzBd25Hbx/nB/wN/JzMUiRMgfHoOKde4RAcWWgzDuwSfYebBfcsVwYSzCxvDvYs
yhapQ7ZE3nw0SHdiNCDRN0mzdsoFcluQ+I0LnYNnNnydrNK97Aoe3SypkITVd8Co
Wx6qLmRNCClUHgS9aP4SIuEVMqHHYSaCjT9GU2FCNWg00J8VC1qIhnufeRjNSfv8
ci6HmpMxt37sJk0GenxGbuofpr0n94YK3IgR6iSlus6btj7BymJ0WG381MfrNPI+
buQQanWz6hmh0WCAdPLFvEc/z5us/H90tiPerBqNiJGf/vytTMKEGGWqTswjyiCW
p3kMyjxGwhVLnrXrSeyKXP5/Q1dVee4G8UPy
=y2HW
-----END PGP PUBLIC KEY BLOCK-----"

echo "$GPG_PUBKEY" | gpg --import


time gpg --recipient guanz@pku.edu.cn --output 1KB.gpg --encrypt 1KB.bin
time gpg --recipient guanz@pku.edu.cn --output 1MB.gpg --encrypt 1MB.bin
time gpg --recipient guanz@pku.edu.cn --output 10MB.gog --encrypt 10MB.bin

