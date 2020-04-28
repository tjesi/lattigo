package dbfv

import (
	"github.com/ldsec/lattigo/ring"
)

//AdditiveShare represents the additive share of the plaintext the party possesses after running the protocol.
//The additive shares are elements of Z_t^n, and add up to the original clear vector, not to its plaintext-encoding.
type AdditiveShare struct {
	ctx  *ring.Context
	elem *ring.Poly
}

// NewAdditiveShare instantiates a new AdditiveShare given its degree and modulus
func NewAdditiveShare(logN uint64, t uint64) *AdditiveShare {
	ctx, _ := ring.NewContextWithParams(1<<logN, []uint64{t})
	return &AdditiveShare{ctx, ctx.NewPoly()}
}

// NewUniformAdditiveShare instantiates a new uniform AdditiveShare given its degree and modulus
func NewUniformAdditiveShare(logN uint64, t uint64) *AdditiveShare {
	ctx, _ := ring.NewContextWithParams(1<<logN, []uint64{t})
	return &AdditiveShare{ctx, ctx.NewUniformPoly()}
}

// SumAdditiveShares describes itself. It is safe to have shareOut coincide with either share1 or share2.
// Requires share1.ctx to be the same as share2.ctx // TODO: enforce this
func SumAdditiveShares(share1, share2, shareOut *AdditiveShare) {
	share1.ctx.Add(share1.elem, share2.elem, shareOut.elem)
}

// EqualSlice compares coefficient-wise
func (x *AdditiveShare) EqualSlice(m []uint64) bool {
	xcoeffs := x.elem.GetCoefficients()[0]

	if len(xcoeffs) != len(m) {
		return false
	}

	for i := range xcoeffs {
		if xcoeffs[i] != m[i] {
			return false
		}
	}

	return true
}

// GetCoeffs returns the coefficients (not copied)
func (x *AdditiveShare) GetCoeffs() []uint64 {
	return x.elem.Coeffs[0]
}
