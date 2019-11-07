# ShadowBreaker
A small program for bruting /etc/shadow files. Writed in education purposes, can be used for testing password policies.

## [!]Compile:
└─g++ main.cpp -lcrypt -pthread -o shadowBreaker --std=c++11

## [!]Usage:
└─./shadowBreaker \<list with passwords\> </etc/shadow file>

## [!]Proof-of-work
<img width="705" alt="for shadowBreaker" src="https://user-images.githubusercontent.com/36220096/68413422-43f85f00-019f-11ea-876a-d914d76e05eb.png">
