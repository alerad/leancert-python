from fractions import Fraction
from decimal import Decimal
from .errors import InexactFloatError, InvalidConstantError

def exact_fraction(value: int | Fraction | Decimal | str) -> Fraction:
    if isinstance(value, bool): raise InvalidConstantError("booleans are not numeric constants")
    if isinstance(value, float): raise InexactFloatError("binary floating-point values are not exact AST constants; use Fraction or rational('0.1')")
    if isinstance(value, (str, Decimal)):
        try: return Fraction(Decimal(value))
        except Exception as exc: raise InvalidConstantError("invalid decimal constant") from exc
    if isinstance(value, (int, Fraction)): return Fraction(value)
    raise InvalidConstantError(f"unsupported constant type: {type(value).__name__}")
