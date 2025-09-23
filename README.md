This project uses submodules, so make sure to clone it with the `--recursive` flag:

```bash
git clone --recursive https://github.com/Hinkiii/sora1looseload.git
```

I suggest building with Release, but either works.

Put xinput1_4.dll into game folder

Will log asset requests that the game makes, and gives the dir it'd load from when not in the cache yet (first load)

Will log strings the game has internally with support for the Japanese character set


For example with this dll you could put

`Trails in the Sky 1st Chapter\asset\dx11\image\st_c5000.dds` to overrride estelles camp sprite
`Trails in the Sky 1st Chapter\script\scena\system.dat` to override system scene script
