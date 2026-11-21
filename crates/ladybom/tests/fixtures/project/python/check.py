import idna
import iniconfig
import packaging

assert idna.encode("café.fr") == b"xn--caf-dma.fr"
assert iniconfig.__name__ == "iniconfig"
assert packaging.__version__ == "25.0"
print("python dependencies OK")
