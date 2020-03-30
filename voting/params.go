package commitment

import (
	"fmt"
)

// Parameters is a struct storing test parameters for the package Comm.
type Parameters struct {
	// LogN is the log2 of the supported polynomial modulus degree.
	LogN      uint64
	// N is supported polynomial modulus degree.
	N         uint64
	//Prime modulus for the NTT
	Modulus   uint64
	//Standard deviation of discrete Gaussians
	Sigma     uint64
	//Height of the commitment matrix
	n         uint64
	//Width (overRq) of the commitment matrices
	k         uint64
	//Maximum l1-norm of elements
	v         uint64
	//∞-norm bound of certain elements
	beta      uint64
}

// MaxLogN is the log2 of the largest supported polynomial modulus degree.
const MaxLogN = 16

// DefaultParams is a set of default parameters ensuring 128 bit security.
var DefaultParams = []*Parameters{
	{LogN: 10,
		N: 1024,
		Modulus: 2490062849,
		Sigma: 46000,
		k: 3,
		n: 3,
		v: 36,
		beta: 1,
	},
}

// Generates a new set of parameters from the input parameters.
func NewParameters(LogN, N, Modulus, Sigma, k, n, v, beta uint64) (params *Parameters) {

	if LogN > MaxLogN {
		panic(fmt.Errorf("cannot NewParametersFromLogModuli: LogN is larger than %d", MaxLogN))
	}

	params = new(Parameters)
	params.LogN = LogN
	params.N = N
	params.Modulus = Modulus
	params.Sigma = Sigma
	params.k = k
	params.n = n
	params.v = v
	params.beta = beta
	return
}

// Copy creates a copy of the target Parameters.
func (p *Parameters) Copy() (paramsCopy *Parameters) {
	paramsCopy = new(Parameters)
	paramsCopy.LogN = p.LogN
	paramsCopy.N = p.N
	paramsCopy.Sigma = p.Sigma
	paramsCopy.Modulus = p.Modulus
	paramsCopy.k = p.k
	paramsCopy.n = p.n
	paramsCopy.v = p.v
	paramsCopy.beta = p.beta
	return
}
