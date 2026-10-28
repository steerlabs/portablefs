"""Evidence parsing must retain host page units and compressed VM bytes."""
import unittest
from linux_workspace_native_pressure import footprint_statistics, vm_statistics


class PressureEvidenceTests(unittest.TestCase):
    def test_host_page_units(self):
        values = vm_statistics('''Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages stored in compressor: 100.
Pages occupied by compressor: 40.
Compressions: 120.
Decompressions: 20.
Swapins: 3.
Swapouts: 8.
''')
        self.assertEqual(values['compressor_stored_bytes'], 1638400)
        self.assertEqual(values['compressor_occupied_bytes'], 655360)
        self.assertEqual(values['swapouts'], 8)

    def test_vm_compression_is_separate_from_resident_bytes(self):
        values = footprint_statistics('''      Dirty     (Swapped)         Clean   Reclaimable    Regions    Category
  4294967296 B    1048576 B           0 B           0 B        544    TOTAL
    phys_footprint: 4296015872 B
''')
        self.assertEqual(values['compressed_swapped_bytes'], 1048576)
        self.assertEqual(values['phys_footprint_bytes'], 4296015872)

    def test_unavailable_vm_is_not_zero_compression(self):
        with self.assertRaises(ValueError): footprint_statistics('process exited')


if __name__ == '__main__': unittest.main()
