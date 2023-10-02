# MiniMPSI

minimpsi implements the PSI protocols in multi-party small set scenarios. Use OKVS to encode set elements, so need to quote Paxos from Vole-PSI.

Vole-PSI implements the protocols described in [VOLE-PSI: Fast OPRF and Circuit-PSI from Vector-OLE](https://eprint.iacr.org/2021/266) and [Blazing Fast PSI from Improved OKVS and Subfield VOLE](misc/blazingFastPSI.pdf). The library implements standard [Private Set Intersection (PSI)](https://en.wikipedia.org/wiki/Private_set_intersection) along with a variant called Circuit PSI where the result is secret shared between the two parties.

The library is cross platform (win,linux,mac) and depends on [libOTe](https://github.com/osu-crypto/libOTe), [sparsehash](https://github.com/sparsehash/sparsehash), [Coproto](https://github.com/Visa-Research/coproto).

### Build

The library can be cloned and built with networking support as
```
git clone https://github.com/xiansongq/minimpsi.git
cd minimpsi
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON 
```


The output library `volepsi`,`miniMPSI`,`cPSI` and executable `frontend` will be written to `out/build/<platform>/`. The `frontend` can perform PSI based on files as input sets and communicate via sockets. See the output of `frontend` for details. 

##### Compile Options
Options can be set as `-D NAME=VALUE`. For example, `-D VOLE_PSI_NO_SYSTEM_PATH=true`. See the output of the build for default/current value. Options include :
 * `VOLE_PSI_NO_SYSTEM_PATH`, values: `true,false`.  When looking for dependencies, do not look in the system install. Instead use `CMAKE_PREFIX_PATH` and the internal dependency management.  
* `CMAKE_BUILD_TYPE`, values: `Debug,Release,RelWithDebInfo`. The build type. 
* `FETCH_AUTO`, values: `true,false`. If true, dependencies will first be searched for and if not found then automatically downloaded.
* `FETCH_SPARSEHASH`, values: `true,false`. If true, the dependency sparsehash will always be downloaded. 
* `FETCH_LIBOTE`, values: `true,false`. If true, the dependency libOTe will always be downloaded. 
* `FETCH_LIBDIVIDE`, values: `true,false`. If true, the dependency libdivide will always be downloaded. 
* `VOLE_PSI_ENABLE_SSE`, values: `true,false`. If true, the library will be built with SSE intrinsics support. 
* `VOLE_PSI_ENABLE_PIC`, values: `true,false`. If true, the library will be built `-fPIC` for shared library support. 
* `VOLE_PSI_ENABLE_ASAN`, values: `true,false`. If true, the library will be built ASAN enabled. 
* `VOLE_PSI_ENABLE_GMW`, values: `true,false`. If true, the GMW protocol will be compiled. Only used for Circuit PSI.
* `VOLE_PSI_ENABLE_CPSI`, values: `true,false`. If true,  the circuit PSI protocol will be compiled. 
* `VOLE_PSI_ENABLE_OPPRF`, values: `true,false`.  If true, the OPPRF protocol will be compiled. Only used for Circuit PSI.
* `VOLE_PSI_ENABLE_BOOST`, values: `true,false`. If true, the library will be built with boost networking support. This support is managed by libOTe. 
* `VOLE_PSI_ENABLE_OPENSSL`, values: `true,false`. If true,the library will be built with OpenSSL networking support. This support is managed by libOTe. If enabled, it is the responsibility of the user to install openssl to the system or to a location contained in `CMAKE_PREFIX_PATH`.
* `VOLE_PSI_ENABLE_BITPOLYMUL`, values: `true,false`. If true, the library will be built with quasicyclic codes for VOLE which are more secure than the alternative. This support is managed by libOTe. 
* `VOLE_PSI_ENABLE_SODIUM`, values: `true,false`. If true, the library will be built libSodium for doing elliptic curve operations. This or relic must be enabled. This support is managed by libOTe. 
* `VOLE_PSI_SODIUM_MONTGOMERY`, values: `true,false`. If true, the library will use a non-standard version of sodium that enables slightly better efficiency. 
* `VOLE_PSI_ENABLE_RELIC`, values: `true,false`. If true, the library will be built relic for doing elliptic curve operations. This or sodium must be enabled. This support is managed by libOTe. 


### Installing

The library and any fetched dependencies can be installed. 
```
python3 build.py --install
```
or 
```
python3 build.py --install=install/prefix/path
```
if a custom install prefix is perfected. Install can also be performed via cmake.



### Dependency Management

By default the dependencies are fetched automatically. This can be turned off by using cmake directly or adding `-D FETCH_AUTO=OFF`. For other options see the cmake output or that of `python build.py --help`.

If the dependency is installed to the system, then cmake should automatically find it if `VOLE_PSI_NO_SYSTEM_PATH` is `false`. If they are installed to a specific location, then you call tell cmake about them as 
```
python3 build.py -D CMAKE_PREFIX_PATH=install/prefix/path
```
Input paraments
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

./out/build/install/frontend/frontend -mpsi -n 5 -m 7 -t 1 -r 0
or
./out/build/install/frontend/frontend -volepsi -m 10 -r 0 -t 1
or
./out/build/install/frontend/frontend -cpsi -m 9 -st 1 -nt 1
or
./out/build/install/frontend/frontend -mycpsi -m 9 -st 1 -nt 1


```
