from memory_model import MemoryModel
import unittest

class TestMemoryModel(unittest.TestCase):
    def setUp(self):
        self.mem = MemoryModel(ram_base=0x80000000, ram_size=0x10000)
        print(f"\nMemory contents before preload:{self.mem.read(0x80000000, 4):#x}")
        self.mem.preload_memory("elf_files/ibex_arithmetic_basic_test_0.o")

  

    def test_read_memory(self):
        self.mem.write(0x80000000,5)
        self.mem.dump_memory("check_memory.txt")
        # Check if the memory was loaded correctly
        print(f"Memory contents after preload:{self.mem.read(0x80000000, 4):#x}")

if __name__ == "__main__":
    unittest.main(verbosity=2)