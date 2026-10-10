package analytics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type AsyncBuffer struct {
	repo          ports.Repository
	ch            chan domain.AnalyticsEvent
	batchSize     int
	flushInterval time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	logger        *slog.Logger
}

func NewAsyncBuffer(repo ports.Repository, bufferCap int, batchSize int, flushInterval time.Duration, logger *slog.Logger) *AsyncBuffer {
	if logger == nil {
		logger = slog.Default()
	}
	b := &AsyncBuffer{
		repo:          repo,
		ch:            make(chan domain.AnalyticsEvent, bufferCap),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		stopCh:        make(chan struct{}),
		logger:        logger,
	}

	b.wg.Add(1)
	go b.worker()

	return b
}

func (b *AsyncBuffer) Enqueue(event domain.AnalyticsEvent) {
	select {
	case b.ch <- event:
	default:
		b.logger.Warn("analytics buffer full, dropping event", "link_id", event.LinkID)
	}
}

func (b *AsyncBuffer) worker() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	batch := make([]domain.AnalyticsEvent, 0, b.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := b.repo.RecordAnalyticsEvents(ctx, batch); err != nil {
			b.logger.Error("failed to record analytics events", "error", err, "count", len(batch))
		}
		batch = make([]domain.AnalyticsEvent, 0, b.batchSize)
	}

	for {
		select {
		case item := <-b.ch:
			batch = append(batch, item)
			if len(batch) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.stopCh:
			// Drain remaining
			for {
				select {
				case item := <-b.ch:
					batch = append(batch, item)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (b *AsyncBuffer) Flush(ctx context.Context) error {
	return nil
}

func (b *AsyncBuffer) Close() error {
	close(b.stopCh)
	b.wg.Wait()
	return nil
}
