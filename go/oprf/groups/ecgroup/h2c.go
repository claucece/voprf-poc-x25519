package ecgroup

import (
	"github.com/alxdavids/voprf-poc/go/oerr"
	h2c "github.com/armfazh/h2c-go-ref"
)

// HashToPoint produces a point by hashing the input message.
type HashToPoint interface {
	Hash(msg []byte) (Point, error)
}

type hasher2point struct {
	GroupCurve
	h2c.HashToPoint
	dst []byte
}

func (h hasher2point) Hash(msg []byte) (Point, error) {
	Q := h.HashToPoint.Hash(msg, h.dst)
	P := Point{}.New(h.GroupCurve).(Point)
	X := Q.X().Polynomial()
	Y := Q.Y().Polynomial()
	P.X.Set(X[0])
	P.Y.Set(Y[0])
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return P, nil
}

func getH2CSuite(gc GroupCurve) (HashToPoint, error) {
	var suite h2c.SuiteID
	var err error
	switch gc.Name() {
	case "P-384":
		suite = h2c.P384_SHA512_SSWU_RO_
	case "P-521":
		suite = h2c.P521_SHA512_SSWU_RO_
	default:
		return nil, oerr.ErrUnsupportedGroup
	}
	dst := append([]byte("RFCXXXX-VOPRF-"), suite...)
	hasher, err := suite.Get()
	if err != nil {
		return nil, err
	}
<<<<<<< HEAD
	return hasher2point{gc, hasher, dst}, nil
=======
	return P, nil
}

// sswu completes the Simplified SWU method curve mapping defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2
func (params h2cParams) sswu(uArr []*big.Int) (Point, error) {
	if len(uArr) > 1 {
		return Point{}, oerr.ErrIncompatibleGroupParams
	}
	u := uArr[0]
	p, A, B, Z := params.p, params.a, params.b, big.NewInt(int64(params.z))

	// consts
	// c1 := -B/A, c2 := -1/Z
	c1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(B, constants.MinusOne), new(big.Int).ModInverse(A, p)), p)
	c2 := new(big.Int).Mul(constants.MinusOne, new(big.Int).ModInverse(Z, p))

	// steps
	t1 := new(big.Int).Mul(Z, new(big.Int).Exp(u, constants.Two, p)) // 1.     t1 = Z * u^2
	t2 := new(big.Int).Exp(t1, constants.Two, p)                     // 2.     t2 = t1^2
	x1 := new(big.Int).Add(t1, t2)                                   // 3.     x1 = t1 + t2
	x1 = utils.Inv0(x1, p)                                           // 4.     x1 = utils.Inv0(x1)
	e1 := utils.EqualsToBigInt(x1, constants.Zero)                   // 5.     e1 = x1 == 0
	x1 = x1.Add(x1, constants.One)                                   // 6.     x1 = x1 + 1
	x1 = utils.Cmov(x1, c2, e1)                                      // 7.     x1 = CMOV(x1, c2, e1)
	x1 = x1.Mul(x1, c1)                                              // 8.     x1 = x1 * c1
	gx1 := new(big.Int).Exp(x1, constants.Two, p)                    // 9.    gx1 = x1^2
	gx1 = gx1.Add(gx1, A)                                            // 10.   gx1 = gx1 + A
	gx1 = gx1.Mul(gx1, x1)                                           // 11.   gx1 = gx1 * x1
	gx1 = gx1.Add(gx1, B)                                            // 12.   gx1 = gx1 + B
	x2 := new(big.Int).Mul(t1, x1)                                   // 13.    x2 = t1 * x1
	t2 = t2.Mul(t1, t2)                                              // 14.    t2 = t1 * t2
	gx2 := new(big.Int).Mul(gx1, t2)                                 // 15.   gx2 = gx1 * t2
	e2 := isSquare(gx1, params.isSqExp, p)                           // 16.    e2 = is_square(gx1)
	x := utils.Cmov(x2, x1, e2)                                      // 17.     x = CMOV(x2, x1, e2)
	y2 := utils.Cmov(gx2, gx1, e2)                                   // 18.    y2 = CMOV(gx2, gx1, e2)
	y := sqrt(y2, params.sqrtExp, p)                                 // 19.     y = sqrt(y2)
	e3 := utils.SgnCmp(u, y, params.sgn0)                            // 20.    e3 = sgn0(u) == sgn0(y)
	y = utils.Cmov(new(big.Int).Mul(y, constants.MinusOne), y, e3)   // 21.     y = CMOV(-y, y, e3)

	// construct point and assert that it is correct
	P := Point{}.New(params.gc).(Point)
	P.X = x.Mod(x, p)
	P.Y = y.Mod(y, p)
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return P, nil
}

// elligator2 implements the Elligator2 method for curve mapping, defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05, section 6.7.1.1.
func (params h2cParams) elligator2(uArr []*big.Int) (Point, error) {
	if len(uArr) > 1 {
		return Point{}, oerr.ErrIncompatibleGroupParams
	}
	u := uArr[0]
	p, A, B, Z := params.p, params.a, params.b, big.NewInt(int64(params.z))

	t1, x1, x2, gx1, gx2, y2, x, y := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)

	t1.Mul(u, u)                                              // t1 = u^2
	t1.Mul(Z, t1)                                             // Z * u^2
	e1 := utils.EqualsToBigInt(t1, new(big.Int).SetInt64(-1)) // Z * u^2 == -1
	t1 = utils.Cmov(t1, new(big.Int).SetInt64(0), e1)         // if t1 == -1, set t1 = 0
	x1.Add(t1, new(big.Int).SetInt64(1))                      // x1 = t1 + 1
	x1 = utils.Inv0(x1, p)                                    // x1 = inv0(x1)
	x1.Mul(new(big.Int).Neg(A), x1)                           // x1 = -A / (1 + Z * u^2)
	gx1.Add(x1, A)                                            // gx1 = x1 + A
	gx1.Mul(gx1, x1)                                          // gx1 = gx1 * x1
	gx1.Add(gx1, B)                                           // gx1 = gx1 + B
	gx1.Mul(gx1, x1)                                          // gx1 = x1^3 + A * x1^2 + B * x1

	x2.Sub(new(big.Int).Neg(x1), A)        //x2 = -x1 - A
	gx2.Mul(t1, gx1)                       // gx2 = t1 * gx1
	e2 := isSquare(gx1, params.isSqExp, p) // e2 = is_square(gx1)
	x = utils.Cmov(x2, x1, e2)             // If is_square(gx1), x = x1, else x = x2
	y2 = utils.Cmov(gx2, gx1, e2)          // If is_square(gx1), y2 = gx1, else y2 = gx2
	y = sqrt(y2, params.sqrtExp, p)        // y = sqrt(y2)
	e3 := utils.SgnCmp(u, y, params.sgn0)
	y = utils.Cmov(new(big.Int).Neg(y), y, e3) // y = CMOV(-y, y, e3)

	x.Mod(x, p)
	y.Mod(y, p)

	// construct point and assert that it is correct
	P := Point{}.New(params.gc).(Point)
	P.X = x
	P.Y = y
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}

	return P, nil
}

// isSquare returns 1 if x is a square integer in FF_p and 0 otherwise, passes
// in the value exp to compute the square root in the exponent
func isSquare(x, exp, p *big.Int) *big.Int {
	b := new(big.Int).Exp(x, exp, p)
	c := b.Cmp(constants.One)
	d := b.Cmp(constants.Zero)
	e := int64(c * d)
	return utils.EqualsToBigInt(big.NewInt(e), constants.Zero) // returns 1 if square, and 0 otherwise
>>>>>>> Implement elligator2 for curve448 and add first test from sage output #9
}

// sqrt computes the sqrt of x mod p (pass in exp explicitly so that we don't
// have to recompute)
func sqrt(x, exp, p *big.Int) *big.Int {
	x = x.Mod(x, p)
	y := new(big.Int).Exp(x, exp, p)
	return y
}
