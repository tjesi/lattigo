package commitment

import (
	"math"
	"crypto/rand"
	"github.com/ldsec/lattigo/ring"
)

// LogN is the log2 of the supported polynomial modulus degree.
const LogN = 10

type committer struct {
	params     *Parameters
	context    *ring.Context
}

type PublicKey struct {
	B1         []*ring.Poly
	b2         []*ring.Poly
}

func setup(params *Parameters) *ring.Context {
	var err error
	var context *ring.Context

	if context, err = ring.NewContextWithParams(params.N, []uint64{params.Modulus}); err != nil {
		panic(err)
	}

	return context
}

func testNorm(com *committer, r *ring.Poly) bool {
	sum := uint64(0);
	for i := range com.context.Modulus {
		for j := uint64(0); j < com.params.N; j++ {
			sum = sum + r.Coeffs[i][j]
		}
	}
	sigma := 11 * float64(com.params.v) * float64(com.params.beta) * math.Sqrt(float64(com.params.k * com.params.N))
	return math.Sqrt(float64(sum)) < 4 * sigma * math.Sqrt(float64(com.params.N))
}

func NewCommitter(params *Parameters) *committer {
	return &committer {
		params:        params.Copy(),
		context:       setup(params),
	}
}

func byteToBits(x byte) []uint64 {
	vec := make([]uint64, 8)
	for bit, mask := 0, 1; bit < 8; bit, mask = bit + 1, mask << 1 {
	     if x & byte(mask) != 0 {
	         vec[bit] = 1
	     }
	}
	return vec
}

func KeyGen(com *committer) (*PublicKey) {
	identity := com.context.NewPoly()
	zero := com.context.NewPoly()
	com.context.SetCoefficientsUint64([]uint64{1}, identity)
	com.context.SetCoefficientsUint64([]uint64{0}, zero)

    return &PublicKey {
	    B1: []*ring.Poly {
		    identity, com.context.NewUniformPoly(), com.context.NewUniformPoly(),
	    },
	    b2: []*ring.Poly {
		    zero, identity, com.context.NewUniformPoly(),
	    },
	}
}

func Sample(com *committer) []*ring.Poly {
	bytes := make([]byte, com.params.N / 8)
	var randomness = []*ring.Poly {
		com.context.NewPoly(), com.context.NewPoly(), com.context.NewPoly(),
	}

	for i := 0; i < 3; i++ {
		if _, err := rand.Read(bytes); err != nil {
			panic("crypto rand error")
		}
		var bits []uint64
		for j := 0; j < int(com.params.N) / 8; j++ {
			bits = append(bits, byteToBits(bytes[j])...)
		}
		com.context.SetCoefficientsUint64(bits, randomness[i])
	}
	return randomness
}

func Commit(com *committer, m *ring.Poly, key *PublicKey, r []*ring.Poly) []*ring.Poly {
	t := com.context.NewPoly()
	c1 := com.context.NewPoly()
	c2 := com.context.NewPoly()
	for i := 0; i < 3; i++ {
		com.context.MulPoly(key.B1[i], r[i], t);
		com.context.Add(c1, t, c1)
		com.context.MulPoly(key.b2[i], r[i], t);
		com.context.Add(c2, t, c2)
	}
	com.context.Add(c2, m, c2)

	return []*ring.Poly { c1, c2 }
}

func Open(com *committer, m *ring.Poly, key *PublicKey, c []*ring.Poly, r []*ring.Poly) bool {
	t := com.context.NewPoly()
	t1 := com.context.NewPoly()
	t2 := com.context.NewPoly()
	for i := 0; i < 3; i++ {
		com.context.MulPoly(key.B1[i], r[i], t);
		com.context.Add(t1, t, t1)
		com.context.MulPoly(key.b2[i], r[i], t);
		com.context.Add(t2, t, t2)
	}
	com.context.Add(t2, m, t2)

	return com.context.Equal(c[0], t1) && com.context.Equal(c[1], t2) &&
	    testNorm(com, r[0]) && testNorm(com, r[1]) && testNorm(com, r[2])
}
