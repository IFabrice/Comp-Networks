'''
>>> from prefix import Prefix
>>> table = ForwardingTable()
>>> table.add_entry('10.20.0.0/23', 'r1-c', '10.30.0.2')
>>> table.add_entry('10.20.0.0/24', 'r1-d', '10.30.0.6')
>>> table.add_entry('10.20.0.0/25', 'r1-e', '10.30.0.10')
>>> table.add_entry('10.20.0.0/26', 'r1-f', '10.30.0.14')
>>> table.add_entry('10.20.0.0/27', 'r1-g', '10.30.0.18')
>>> table.add_entry('10.20.0.0/28', 'r1-h', '10.30.0.22')
>>> table.add_entry('10.20.0.0/29', 'r1-i', '10.30.0.26')
>>> table.add_entry('10.20.0.0/30', 'r1-j', '10.30.0.30')
>>> table.add_entry('0.0.0.0/0', 'r1-k', '10.30.0.34')

Test the ForwardingTable.get_entry() method
>>> table.get_entry('10.20.0.25')
('r1-g', '10.30.0.18')
>>> table.get_entry('10.20.0.34')
('r1-f', '10.30.0.14')
>>> table.get_entry('10.20.1.20')
('r1-c', '10.30.0.2')
>>> table.get_entry('10.20.3.1')
('r1-k', '10.30.0.34')
>>> table.get_entry('10.20.0.2')
('r1-j', '10.30.0.30')
>>> table.get_entry('10.20.0.11')
('r1-h', '10.30.0.22')
>>> table.get_entry('10.20.0.150')
('r1-d', '10.30.0.6')
>>> table.get_entry('10.20.0.7')
('r1-i', '10.30.0.26')
>>> table.get_entry('10.20.0.75')
('r1-e', '10.30.0.10')
'''



from prefix import Prefix
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

class ForwardingTable(object):
    def __init__(self):
        self.entries = {}

    def add_entry(self, prefix: str, intf: str, next_hop: str) -> None:
        '''Add forwarding entry mapping prefix to interface and next hop
        IP address.'''

        prefix = Prefix(prefix)

        if intf is None:
            intf, next_hop1 = self.get_entry(next_hop)

        self.entries[prefix] = (intf, next_hop)

    def remove_entry(self, prefix: str) -> None:
        '''Remove the forwarding entry matching prefix.'''

        prefix = Prefix(prefix)

        if prefix in self.entries:
            del self.entries[prefix]

    def flush(self, family: int=None, global_only: bool=True) -> None:
        '''Flush the routing table.'''

        routes = self.get_all_entries(family=family, \
                resolve=False, global_only=global_only)

        for prefix in routes:
            del self.entries[prefix]

    def get_entry(self, address: str):
        '''Return the subnet entry having the longest prefix match of
        address.  The   entry is a tuple consisting of interface and
        next-hop IP address.  If there is no match, return None, None.'''

        max_length = -1
        max_length_entry = None
	    #TODO:  Complete the for loop for to check the address in each entry using the longest prefix match      

        for prefix in self.entries:            
            if prefix.__contains__(address) and max_length < prefix.prefix_len:
                max_length_entry = self.entries[prefix]
                max_length = prefix.prefix_len

        if max_length_entry is not None:
            return max_length_entry
        
        return None, None
    
    def get_all_entries(self, family: int=None,
            resolve: bool=False, global_only: bool=True):

        entries = {}
        for prefix in self.entries:
            intf, next_hop = self.entries[prefix]
            if next_hop is not None or not global_only:
                entries[prefix] = (intf, next_hop)
        return entries
