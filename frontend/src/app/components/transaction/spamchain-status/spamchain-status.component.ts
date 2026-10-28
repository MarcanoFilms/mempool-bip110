import { Component, Input, OnChanges, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ApiService } from '@app/services/api.service';
import { SpamchainStatus } from '@interfaces/node-api.interface';

@Component({
  selector: 'app-spamchain-status',
  templateUrl: './spamchain-status.component.html',
  styleUrls: ['./spamchain-status.component.scss'],
  standalone: false,
})
export class SpamchainStatusComponent implements OnChanges, OnDestroy {
  @Input() txid: string;

  status: SpamchainStatus | null = null;
  loading = false;
  private subscription: Subscription;

  constructor(private apiService: ApiService) {}

  ngOnChanges(): void {
    this.status = null;
    this.subscription?.unsubscribe();
    if (!this.txid) {
      return;
    }
    this.loading = true;
    this.subscription = this.apiService.getTransactionSpamchain$(this.txid).subscribe({
      next: (status) => {
        this.status = status;
        this.loading = false;
      },
      error: () => {
        this.status = { status: 'error' };
        this.loading = false;
      },
    });
  }

  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }
}
