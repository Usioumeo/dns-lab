import z3

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
# Replace with your actual taps and bit sizes
TAP1 = 0x80000057  # Example 32-bit tap
TAP2 = 0x80000062  # Example 32-bit tap
STATE_BITS = 32

# Replace this array with the 20 TXIDs you leaked via your script
leaked_outputs = [7736, 3868, 34702, 50119, 50641, 55324, 13898, 3464, 49946, 28892, 14446, 7223, 14841, 934, 49350, 28715]

# ---------------------------------------------------------
# SYMBOLIC FUNCTIONS
# ---------------------------------------------------------
def z3_generate(state, tap):
    """
    Symbolic representation of the LFSR step.
    ** MODIFY THIS IF YOUR generate() DIFFERS **
    Assumes standard Galois LFSR: shift right, XOR with tap if LSB was 1.
    """
    lsb = state & 0x1
    # MUST use LShR for logical shift right in Z3, NOT >>
    shifted = z3.LShR(state, 1)
    return z3.If(lsb == 1, shifted ^ tap, shifted)

def z3_step_cross(lfsr1, lfsr2, tap1, tap2):
    """
    Symbolic equivalent of your step_cross function.
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

# ---------------------------------------------------------
# SOLVER EXECUTION
# ---------------------------------------------------------
print("[*] Initializing Z3 Solver...")
s = z3.Solver()

# Define the initial unknown symbolic states
state1 = z3.BitVec('lfsr1_init', STATE_BITS)
state2 = z3.BitVec('lfsr2_init', STATE_BITS)

# Keep track of the moving state variables
curr_state1 = state1
curr_state2 = state2

# Feed the 20 leaked outputs into the solver's constraints
print(f"[*] Feeding {len(leaked_outputs)} leaked TXIDs into constraints...")
for i, leak in enumerate(leaked_outputs):
    curr_state1, curr_state2, out = z3_step_cross(curr_state1, curr_state2, TAP1, TAP2)
    s.add(out == leak)

# ---------------------------------------------------------
# CRACKING AND PREDICTION
# ---------------------------------------------------------
print("[*] Solving for initial states...")
if s.check() == z3.sat:
    m = s.model()
    
    # Extract the recovered initial states
    found_init1 = m[state1].as_long()
    found_init2 = m[state2].as_long()
    
    print(f"[+] SUCCESS! Model Satisfied.")
    print(f"[+] Initial LFSR 1 State: {hex(found_init1)}")
    print(f"[+] Initial LFSR 2 State: {hex(found_init2)}")
    
    # Now that we know the initial states, let's fast-forward 
    # to the current state to predict the NEXT valid TXID
    
    # Copy the found states into standard python integers
    # (Assuming we have a python version of generate() to run)
    
    # To predict purely inside Z3, we can just evaluate the curr_state variables
    next_state1, next_state2, next_txid = z3_step_cross(curr_state1, curr_state2, TAP1, TAP2)
    
    predicted_id = m.eval(next_txid).as_long()
    print(f"\n[!] The NEXT valid TXID (Prediction #{len(leaked_outputs) + 1}) is: {predicted_id} (0x{predicted_id:04x})")
    
else:
    print("[-] UNSAT. The solver could not find a valid state.")
    print("    Double-check your taps, your generate() logic, and ensure the leaks are contiguous.")