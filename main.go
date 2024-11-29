package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

// 生成钱包地址，并检测是否符合目标的工作函数
func generateWalletWithPrefixSuffix(ctx context.Context, prefix, suffix string, found chan<- *ecdsa.PrivateKey, attempts *uint64) {
	bytes := make([]byte, 32)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// 生成随机 bytes
			rand.Read(bytes)

			// 生成私钥、公钥
			// privateKey, _ := crypto.GenerateKey()
			privateKey := crypto.ToECDSAUnsafe(bytes)
			address := crypto.PubkeyToAddress(privateKey.PublicKey)
			addressStr := address.Hex()[2:]

			// 尝试计数 +1
			atomic.AddUint64(attempts, 1)

			// 检测是否符合用户设定的规则
			if strings.HasPrefix(addressStr, prefix) && strings.HasSuffix(addressStr, suffix) {
				select {
				case found <- privateKey:
					return
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// 输出计算进度日志
func logAttempts(startTime time.Time, totalDiff uint64, logInterval uint64, attempts *uint64) {
	ticker := time.NewTicker(time.Duration(logInterval) * time.Second)
	defer ticker.Stop()

	var lastCount uint64
	for range ticker.C {
		// 计算本次速度
		currentCount := atomic.LoadUint64(attempts)
		speed := (currentCount - lastCount) / logInterval
		lastCount = currentCount

		// 计算总体速度
		duration := time.Since(startTime)
		totalSeconds := duration.Seconds()
		totalSpeed := currentCount / uint64(totalSeconds)

		// 计算剩余时间
		var eta int64
		if totalDiff > currentCount {
			eta = int64((totalDiff - currentCount) / totalSpeed)
		} else {
			eta = -int64((currentCount - totalDiff) / totalSpeed)
		}

		// 输出日志
		fmt.Printf("[%s] Speed: %d/s, Avg: %d/s, Progress: %d / %d (%.2f%%), Used: %ds, ETA: %ds\n", time.Now().Format("15:04:05"), speed, totalSpeed, currentCount, totalDiff, (float64(currentCount)/float64(totalDiff))*100, uint64(totalSeconds), eta)
	}
}

func main() {
	var prefix, suffix string
	var threadCount int
	var logInterval uint64

	var rootCmd = &cobra.Command{
		Use:   "./rare_eth",
		Short: "ETH nice number generator",
		Run: func(cmd *cobra.Command, args []string) {
			startTime := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			found := make(chan *ecdsa.PrivateKey)
			var wg sync.WaitGroup

			// 统计尝试次数的变量
			var attempts uint64 = 0

			// 启动日志统计
			var diff uint64 = uint64(math.Pow(16, float64(len(prefix)+len(suffix))))
			go logAttempts(startTime, diff, logInterval, &attempts)

			for i := 0; i < threadCount; i++ {
				wg.Add(1)
				go func() {
					generateWalletWithPrefixSuffix(ctx, prefix, suffix, found, &attempts)
					wg.Done()
				}()
			}

			// 得到计算出的私钥，计算出公钥，并转出 Hex 格式
			privateKey := <-found
			address := crypto.PubkeyToAddress(privateKey.PublicKey)
			privateKeyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))

			// 输出结果地址的公私钥
			fmt.Printf("Found address: %s\n", address.Hex())
			fmt.Printf("Private key: 0x%s\n", privateKeyHex)

			// 等待其他工作线程完成
			cancel()
			wg.Wait()

			// 输出用时日志
			duration := time.Since(startTime)
			hours := int(duration.Hours())
			minutes := int(duration.Minutes()) % 60
			seconds := int(duration.Seconds()) % 60
			fmt.Printf("Used: %dh %dm %ds, Total try count: %d\n", hours, minutes, seconds, attempts)
		},
	}

	// 注册参数
	rootCmd.Flags().StringVarP(&prefix, "prefix", "p", "", "Destination address prefix, default is unlimited")
	rootCmd.Flags().StringVarP(&suffix, "suffix", "s", "", "Destination address suffix, default is unlimited")
	rootCmd.Flags().IntVarP(&threadCount, "threads", "t", runtime.NumCPU(), "Thread count, default is cpu count")
	rootCmd.Flags().Uint64VarP(&logInterval, "logInterval", "l", 60, "Print log interval(seconds), default is 60")

	// 运行命令
	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
