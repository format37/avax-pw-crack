clear
[ -f "master" ] && rm master
gcc master.c -o master -lcrypto
