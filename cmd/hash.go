/*
Copyright © 2023 Nuno Alves <nunodpalves@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Print checksums of inputed data",
	Long:  `Crypto is a CLI tool that prints checksums using the crypto Go package.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().NFlag() == 0 {
			return errors.New("No hash function selected.")
		}

		// If there's no args message, read from stdin.
		message := strings.Join(args, "")
		if message == "" {
			reader := bufio.NewReader(os.Stdin)
			message, _ = reader.ReadString('\n')
			message = strings.TrimSuffix(message, "\n")
		}

		// Run through the selected hash function flags.
		cmd.Flags().Visit(func(flag *pflag.Flag) {
			var h hash.Hash
			switch flag.Name {
			case "md5":
				h = md5.New()
			case "sha224":
				h = sha256.New224()
			case "sha256":
				h = sha256.New()
			case "sha384":
				h = sha512.New384()
			case "sha512":
				h = sha512.New()
			case "sha512_224":
				h = sha512.New512_224()
			case "sha512_256":
				h = sha512.New512_256()
			}
			h.Write([]byte(message))
			fmt.Printf("%x\n", h.Sum(nil))
		})

		return nil
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)

	hashCmd.Flags().SortFlags = false
	hashCmd.Flags().Bool("md5", false, "Use the MD5 cryptographic hash function.")
	hashCmd.Flags().Bool("sha224", false, "Use the SHA224 cryptographic hash function.")
	hashCmd.Flags().Bool("sha256", false, "Use the SHA256 cryptographic hash function.")
	hashCmd.Flags().Bool("sha384", false, "Use the SHA384 cryptographic hash function.")
	hashCmd.Flags().Bool("sha512", false, "Use the SHA512 cryptographic hash function.")
	hashCmd.Flags().Bool("sha512_224", false, "Use the SHA512_224 cryptographic hash function.")
	hashCmd.Flags().Bool("sha512_256", false, "Use the SHA512_256 cryptographic hash function.")
}
