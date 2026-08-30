"""Mimar: a security architecture tool.

Named for the Arabic word for architect. Mimar takes a short description of a
system, its trust zones, its components, and the flows of data between them, and
turns it into a threat model: the diagram, a STRIDE threat register, and a list
of the weaknesses in the shape of the architecture itself, each with the control
that would fix it. It is design time and defensive, with zero dependencies.
"""
__version__ = "0.1.0"
