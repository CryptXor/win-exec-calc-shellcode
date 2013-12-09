import os, re;
# I got the actual size of the binary code wrong on the site once - this script should help prevent that.

dsDoc_by_sArch = {"w32": "x86", "w64": "x64", "win": "x86+x64"};
with open("build_info.txt", "rb") as oFile:
  iBuildNumber = int(re.search(r"build number\: (\d+)", oFile.read(), re.M).group(1));

print "Sizes (build %d)" % iBuildNumber;

for sArch in sorted(dsDoc_by_sArch.keys()):
  sDoc = dsDoc_by_sArch[sArch];
  iBinSize = os.path.getsize(r"build\bin\%s-exec-calc-shellcode.bin" % sArch);
  iBinESPSize = os.path.getsize(r"build\bin\%s-exec-calc-shellcode-esp.bin" % sArch);
  try:
    iBinFuncSize = os.path.getsize(r"build\bin\%s-exec-calc-shellcode-func.bin" % sArch);
    iBinCleanFuncSize = os.path.getsize(r"build\bin\%s-exec-calc-shellcode-clean-func.bin" % sArch);
  except:
    print "  * %s: %d bytes (%d w/ stack align)" % (sDoc, iBinSize, iBinESPSize);
  else:
    print "  * %s: %d bytes (%d w/ stack align, %d w/ function wrapper, %d w/ function wrapper + save all registers)" % (sDoc, iBinSize, iBinESPSize, iBinFuncSize, iBinCleanFuncSize);
