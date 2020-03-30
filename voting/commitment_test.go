package commitment

import (
	"fmt"
	"testing"
)

func TestCommitment(t *testing.T) {
	var com *committer = NewCommitter(DefaultParams[0])

	key := KeyGen(com)
	m := com.context.NewUniformPoly()
	rho := com.context.NewUniformPoly()

	identity := com.context.NewPoly()
	com.context.SetCoefficientsUint64([]uint64{1}, identity)

	r := Sample(com)
	z0 := Commit(com, m, key, r)
	fmt.Println("Valid commitment can be opened:", Open(com, m, key, z0, r));
	com.context.Sub(m, identity, m)
	fmt.Println("Invalid commitment cannot be opened:", !Open(com, m, key, z0, r));

	zero := Sample(com)
	for k := 0; k < 3; k++ {
		for i := range com.context.Modulus {
			for j := uint64(0); j < com.params.N; j++ {
				zero[k].Coeffs[i][j] = 0
			}
		}
	}
	z0 = Commit(com, m, key, r)
	z1 := Commit(com, rho, key, zero)

	com.context.Sub(z0[0], z1[0], z0[0]);
	com.context.Sub(z0[1], z1[1], z0[1]);
	com.context.Sub(m, rho, m)

	fmt.Println("Commitment is linearly homomorphic:", Open(com, m, key, z0, r));
}

func BenchmarkCommit(b *testing.B) {
    var com *committer = NewCommitter(DefaultParams[0])

	key := KeyGen(com)
	randomness := Sample(com)
	message := com.context.NewUniformPoly()

	identity := com.context.NewPoly()
	com.context.SetCoefficientsUint64([]uint64{1}, identity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Commit(com, message, key, randomness)
	}
}

func BenchmarkOpen(b *testing.B) {
    var com *committer = NewCommitter(DefaultParams[0])

	key := KeyGen(com)
	randomness := Sample(com)
	message := com.context.NewUniformPoly()

	identity := com.context.NewPoly()
	com.context.SetCoefficientsUint64([]uint64{1}, identity)

	z0 := Commit(com, message, key, randomness)

	b.ResetTimer()
	for i := 0; i < int(com.params.N); i++ {
		Open(com, message, key, z0, randomness)
	}
}
