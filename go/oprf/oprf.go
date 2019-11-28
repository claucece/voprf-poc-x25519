package oprf

import (
	"errors"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

var (
	// ErrOPRFCiphersuiteUnsupportedFunction indicates that the given OPRF
	// function is not supported for the configuration specified by the
	// ciphersuite
	ErrOPRFCiphersuiteUnsupportedFunction = errors.New("Chosen OPRF function is not yet supported for the chosen ciphersuite")
	// ErrOPRFUnimplementedFunctionClient indicates that the function that has been
	// called is not implemented for the client in the OPRF protocol
	ErrOPRFUnimplementedFunctionClient = errors.New("Function is unimplemented for the OPRF client")
	// ErrOPRFUnimplementedFunctionServer indicates that the function that has been
	// called is not implemented for the server in the OPRF protocol
	ErrOPRFUnimplementedFunctionServer = errors.New("Function is unimplemented for the OPRF server")
)

// PublicKey represents a commitment to a given secret key that is made public
// during the OPRF protocol
type PublicKey gg.GroupElement

// SecretKey represents a scalar value controlled by the server in an OPRF
// protocol
type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}

// New returns a SecretKey object corresponding to the PrimeOrderGroup that was
// passed into it
func (sk SecretKey) New(pog gg.PrimeOrderGroup) (SecretKey, error) {
	randInt, err := pog.UniformFieldElement()
	if err != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: Y}, nil
}

// The Participant interface defines the functions necessary for implenting an OPRF
// protocol
type Participant interface {
	Ciphersuite() gg.Ciphersuite
	Setup(string, gg.PrimeOrderGroup) (Participant, error)
	Blind([]byte) (gg.GroupElement, *big.Int, error)
	Unblind(gg.GroupElement, *big.Int) (gg.GroupElement, error)
	Eval(SecretKey, gg.GroupElement) (gg.GroupElement, error)
	Finalize(gg.GroupElement, []byte, []byte) ([]byte, error)
}

// Server implements the OPRF interface for processing the server-side
// operations of the OPRF protocol
type Server struct {
	ciph gg.Ciphersuite
	sk   SecretKey
}

// Ciphersuite returns the Ciphersuite object associated with the Server
func (s Server) Ciphersuite() gg.Ciphersuite { return s.ciph }

// SecretKey returns the SecretKey object associated with the Server
func (s Server) SecretKey() SecretKey { return s.sk }

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}

	sk, err := SecretKey{}.New(ciph.POG())
	if err != nil {
		return nil, err
	}

	s.ciph = ciph
	s.sk = sk
	return s, nil
}

// Eval computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
//
// TODO: support VOPRF
func (s Server) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, error) {
	ciph := s.ciph
	var Z gg.GroupElement
	var err error
	if !ciph.Verifiable() {
		Z, err = M.ScalarMult(sk.K)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ErrOPRFCiphersuiteUnsupportedFunction
	}
	return Z, nil
}

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	return nil, nil, ErrOPRFUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, error) {
	return nil, ErrOPRFUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	return nil, ErrOPRFUnimplementedFunctionServer
}

// Client implements the OPRF interface for processing the client-side
// operations of the OPRF protocol
type Client struct {
	ciph gg.Ciphersuite
	pk   PublicKey
}

// Ciphersuite returns the Ciphersuite object associated with the Client
func (c Client) Ciphersuite() gg.Ciphersuite { return c.ciph }

// PublicKey returns the PublicKey object associated with the Client
func (c Client) PublicKey() PublicKey { return c.pk }

// Setup associates the client with a ciphersuite object
func (c Client) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}
	c.ciph = ciph
	return c, nil
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog
func (c Client) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	pog := c.ciph.POG()

	// encode bytes to group
	T, err := pog.EncodeToGroup(x)
	if err != nil {
		return nil, nil, err
	}

	// sample a random blind
	r, err := pog.UniformFieldElement()
	if err != nil {
		return nil, nil, err
	}

	// compute blinded group element
	P, err := T.ScalarMult(r)
	if err != nil {
		return nil, nil, err
	}
	rInv := new(big.Int).ModInverse(r, pog.Order())
	Tchk, err := P.ScalarMult(rInv)
	return P, r, nil
}

// Unblind returns the unblinded group element N = r^{-1}*Z
//
// TODO: support VOPRF
func (c Client) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, error) {
	ciph := c.ciph
	pog := c.ciph.POG()
	p := pog.Order()

	if ciph.Verifiable() {
		return nil, ErrOPRFCiphersuiteUnsupportedFunction
	}

	rInv := new(big.Int).ModInverse(r, p)
	N, err := Z.ScalarMult(rInv)
	if err != nil {
		return nil, err
	}
	return N, nil
}

// Finalize constructs the final client output from the OPRF protocol
func (c Client) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	ciph := c.ciph
	DST := []byte("oprf_derive_output")

	// derive shared key
	hmacShared := (ciph.H2())(ciph.H3, DST)
	NBytes, err := N.Serialize()
	if err != nil {
		return nil, err
	}
	hmacShared.Write(x)
	dk := hmacShared.Sum(NBytes)

	// derive output
	hmacOut := (ciph.H2())(ciph.H3, dk)
	y := hmacOut.Sum(aux)
	return y, nil
}

// Eval is not implemented for the OPRF client
func (c Client) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, error) {
	return nil, ErrOPRFUnimplementedFunctionClient
}
