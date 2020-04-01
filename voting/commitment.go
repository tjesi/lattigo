package commitment

import (
	"math/big"
	"crypto/rand"
	"encoding/binary"
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

	if context, err = ring.NewContextWithParams(uint64(params.N), []uint64{params.Modulus}); err != nil {
		panic(err)
	}

	return context
}

func l2Norm(com *committer, r *ring.Poly) *big.Int {
	sum := big.NewInt(0)
	poly := make([]*big.Int, com.context.N)
	com.context.PolyToBigint(r, poly)

	for i := range com.context.Modulus {
		sum = sum.Add(sum, poly[i].Mul(poly[i], poly[i]))
	}
	return sum
}

func testNorm(com *committer, r *ring.Poly) bool {
	sum := l2Norm(com, r)

	// Actually compute sigma^2 to simplify comparison
	//sigma := 11 * 11 * (com.params.v * com.params.v) * (com.params.beta * com.params.beta) * com.params.k * com.params.N
	return sum.Uint64() * sum.Uint64() <= (16 * uint64(com.params.Sigma * uint64(com.params.N)))
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
	coeffs := make([]uint64, com.params.N)
	bytes := make([]byte, 8)
	var randomness = []*ring.Poly {
		com.context.NewPoly(), com.context.NewPoly(), com.context.NewPoly(),
	}

	for i := 0; i < com.params.k; i++ {
		for j := 0; j < com.params.N; j++ {
			if _, err := rand.Read(bytes); err != nil {
				panic("crypto rand error")
			}
			coeffs[j] = binary.LittleEndian.Uint64(bytes) % 2
		}
		com.context.SetCoefficientsUint64(coeffs, randomness[i])
	}
	return randomness
}

func SampleChallenge(com *committer) *ring.Poly {
	coeffs := make([]uint64, com.params.N)
	challenge := com.context.NewPoly()
	var c = []*ring.Poly {
		com.context.NewPoly(), com.context.NewPoly(),
	}

	for com.context.Equal(c[0], c[1]) == true {
		for j := 0; j < 2; j++ {
			for i := 0; i < com.params.N; i++ {
				coeffs[i] = 0
			}
			for i := 0; i < com.params.v; i++ {
				bytes := make([]byte, 8)
				if _, err := rand.Read(bytes); err != nil {
					panic("crypto rand error")
				}
				coeffs[binary.LittleEndian.Uint64(bytes) % uint64(com.params.N)] = 1
			}
			com.context.SetCoefficientsUint64(coeffs, c[j])
		}
	}

	com.context.Sub(c[0], c[1], challenge)
	return challenge
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

func Open(com *committer, m *ring.Poly, key *PublicKey, c []*ring.Poly, r []*ring.Poly, f *ring.Poly) bool {
	identity := com.context.NewPoly()
	com.context.SetCoefficientsUint64([]uint64{1}, identity)

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

	return testNorm(com, r[0]) && testNorm(com, r[1]) && testNorm(com, r[2]) &&  com.context.Equal(c[0], t1) && com.context.Equal(c[1], t2)

}
