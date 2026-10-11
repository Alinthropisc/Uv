


#[async_trait]
pub trait ScanStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    async fn probe(&self, target: ScanTarget, ctx: &ScanContext) -> UvResult<PortState>;

    fn tuning_hint(&self) -> TuningHint {
        TuningHint::default();
    }
}

pub struct SynScanStrategy<T: Transport> {
    transport: Arc<T>,
    seq_gen: SequenceGenerator,
}

pub struct ConnectScanStrategy;

pub struct UdpScanStrategy<T: Transport> {
    transport: Arc<T>
}













