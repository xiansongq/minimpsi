# MiniMPSI

minimpsi implements the PSI protocols in multi-party small set scenarios. Use OKVS to encode set elements, so need to quote Paxos from Vole-PSI.


The library is cross platform (win,linux,mac) and depends on [volePSI](https://github.com/Visa-Research/volepsi), [libOTe](https://github.com/osu-crypto/libOTe), [sparsehash](https://github.com/sparsehash/sparsehash), [Coproto](https://github.com/Visa-Research/coproto).

### Environment
```
ubuntu 16.04.4
gcc 9.4.0
g++ 9.4.0
cmake 3.20.1
make 4.1
```

### Installation
```
git clone https://github.com/xiansongq/minimpsi.git
cd minimpsi

git clone https://github.com/Visa-Research/volepsi.git
cd volepsi
git checkout 687ca2dd03fd663a216b6ede9d2707f6d5b10b00

#compaile and install volepsi
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_GMW=ON -DVOLE_PSI_ENABLE_CPSI=ON -DVOLE_PSI_ENABLE_OPPRF=ON

python3 build.py --install=../libvolepsi

cp out/build/linux/volePSI/config.h ../libvolepsi/include/volePSI/

cd ..
```

### Build
```
mkdir build && cd build
cmake ..
make
```
### Running the code
```
./main
```



### Input paraments
```
-mpsi: Run the multiparity mini PSI.
      -n: number of parties.
      -m: input set size ( 2^m ).
      -mm: input set size ( mm ).
      -p: the party ID (must be a continuous integer of 1-n ) Local Multi-Terminal Time Input.
      -t: number of threads.
      -r: 0 is semihonest model, 1 is malicous model.
-cpsi: Run  RS21 circuit psi.
      -m <value>: the log2 size of the sets.
      -st: ValueShareType (1 xor,0 add32).
      -t: number of threads.
-mycpsi: Run our circuit psi.
      -m <value>: the log2 size of the sets.
      -st: ValueShareType (1 xor,0 add32).
      -t: number of threads.
-volepsi: Run the volePSI.
      -m <value>: the log2 size of the sets.
      -r: 0 is semihonest model, 1 is malicous model.
      -t: number of threads.

```
For example

```Bash

./build/miniMPSI -mpsi -n 5 -m 7 -t 1 -r 0
or
./build/miniMPSI -volepsi -m 10 -r 0 -t 1
or
./build/miniMPSI -cpsi -m 9 -st 1 -nt 1
or
./build/miniMPSI -mycpsi -m 9 -st 1 -nt 1


```
