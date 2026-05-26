package main

import (
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"os"
)

func resize256(img image.Image) image.Image {
	rect := image.Rect(0, 0, 256, 256)
	dst := image.NewRGBA(rect)
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			srcX := x * w / 256
			srcY := y * h / 256
			dst.Set(x, y, img.At(bounds.Min.X+srcX, bounds.Min.Y+srcY))
		}
	}
	return dst
}

func main() {
	inPath := "GoVersionML/winres/icon.png"
	if len(os.Args) > 1 {
		inPath = os.Args[1]
	}

	outPath := inPath
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}

	fmt.Printf("Reading %s...\n", inPath)
	fIn, err := os.Open(inPath)
	if err != nil {
		panic(err)
	}

	img, _, err := image.Decode(fIn)
	if err != nil {
		fIn.Close()
		panic(err)
	}
	fIn.Close()

	fmt.Println("Resizing to 256x256...")
	resized := resize256(img)

	fmt.Printf("Writing resized image to %s...\n", outPath)
	fOut, err := os.Create(outPath)
	if err != nil {
		panic(err)
	}
	defer fOut.Close()

	err = png.Encode(fOut, resized)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done successfully!")
}

