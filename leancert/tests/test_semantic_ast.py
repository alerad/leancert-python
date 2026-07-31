from dataclasses import FrozenInstanceError
from fractions import Fraction
import json
import pickle
import pytest
import leancert.ast as lc

def test_first_slice_round_trip_and_digest():
    x=lc.var("x")
    claim=lc.sin(x)+Fraction(1,2)*x**2 <= 1
    canonical=lc.normalize(claim)
    assert lc.normalize(canonical)==canonical
    assert lc.decode_canonical(lc.encode_canonical(canonical))==canonical
    assert lc.semantic_digest(claim)==lc.semantic_digest(canonical)

def test_float_and_truth_rejected():
    x=lc.var("x")
    with pytest.raises(lc.InexactFloatError):lc.const(.1)
    with pytest.raises(TypeError,match="no Python truth value"):bool(x<=1)
    with pytest.raises(TypeError,match="chained comparisons"):eval("0 <= x <= 1")

def test_normalization_equivalences():
    x=lc.var("x"); y=lc.var("y")
    assert lc.semantically_equal(x+0,x)
    assert lc.semantically_equal(x+y,y+x)
    assert lc.semantically_equal(x>=0,0<=x)
    assert lc.normalize(lc.sin(0))==lc.const(0,lc.REAL)

def test_identity_domain_and_metadata():
    x=lc.var("x",namespace="a"); y=lc.var("x",namespace="b")
    assert x!=y
    b1=lc.box({x:(0,1),y:(0,2)}); b2=lc.box({y:(0,2),x:(0,1)})
    assert lc.semantic_digest(b1)==lc.semantic_digest(b2)
    assert lc.semantic_digest(lc.Annotated(x,{"span":lc.SourceSpan("a.py",1,2)}))==lc.semantic_digest(x)

def test_immutable_hashable_pickle():
    x=lc.var("θ"); hash(x); assert pickle.loads(pickle.dumps(x))==x
    with pytest.raises(FrozenInstanceError):x.symbol=object()

def test_strict_duplicate_key_and_version():
    with pytest.raises(lc.AstDecodeError):lc.decode_canonical('{"schema":"leancert.ast","schema":"x","version":1,"root":{}}')
    with pytest.raises(lc.UnknownAstNodeVersion):lc.decode_canonical({"schema":"leancert.ast","version":2,"root":{}})

def test_external_authoritative_identity():
    p=lc.PackageIdentity("pkg","git","abc")
    f=lc.external_unary("Pkg.f",p,"pkg.f.v1")
    with pytest.raises(lc.UnresolvedExternalIdentityError):lc.semantic_digest(lc.FunctionCall(f,(lc.var("x"),)))

def test_eventual_cutoff_round_trip():
    n=lc.var("n",sort=lc.NATURAL)
    claim=lc.eventually(3/n**2 <= Fraction(1,1000),variable=n,cutoff=100)
    assert claim.explicit_cutoff==lc.const(100)
    decoded=lc.decode_canonical(lc.encode_canonical(claim))
    assert lc.alpha_equivalent(decoded,claim)
    assert decoded.explicit_cutoff==lc.const(100)

def test_named_constants_transcendentals_and_derivative():
    x=lc.var("x")
    assert lc.sin(lc.pi).sort==lc.REAL
    for fn in (lc.arcsin,lc.arccos,lc.sinh,lc.cosh,lc.tanh,lc.sinc,lc.erf):assert fn(x).sort==lc.REAL
    derivative=lc.derivative(lc.sin(x),x)
    assert lc.decode_canonical(lc.encode_canonical(derivative))==derivative

def test_system_equality_is_converted_to_zero_residual():
    x=lc.var("x"); domain=lc.box({x:(0,1)})
    claim=lc.system_root_exists((lc.eq(x,1),),variables=(x,),within=domain)
    assert isinstance(claim.equations[0],lc.Add)
    with pytest.raises(TypeError,match="f = 0"):
        lc.system_root_exists((x<1,),variables=(x,),within=domain)
