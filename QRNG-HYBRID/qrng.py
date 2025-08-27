# save as qrng.py
from qiskit import QuantumCircuit
from qiskit_aer import Aer

def qrng_bits(n_bits: int) -> str:
    """Return a string of n_bits random bits from a 1-qubit H+measure experiment."""
    qc = QuantumCircuit(1, 1)
    qc.h(0); qc.measure(0, 0)
    backend = Aer.get_backend("qasm_simulator")
    job = backend.run(qc, shots=n_bits, memory=True)   # memory=True gives per-shot outcomes
    mem = job.result().get_memory()                    # e.g., ['0','1','1',...]
    return "".join(mem)

def bits_to_bytes(bitstr: str) -> bytes:
    if not bitstr:
        return b""
    # left-pad to multiple of 8
    pad = (-len(bitstr)) % 8
    bitstr = ("0"*pad) + bitstr
    return int(bitstr, 2).to_bytes(len(bitstr)//8, "big")

def qrng_bytes(n_bytes: int) -> bytes:
    return bits_to_bytes(qrng_bits(n_bytes*8))
