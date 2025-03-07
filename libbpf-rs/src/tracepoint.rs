use std::mem::size_of;


/// Options to optionally be provided when attaching to a tracepoint.
#[derive(Clone, Debug, Default)]
pub struct TracepointOpts {
    /// Custom user-provided value accessible through `bpf_get_attach_cookie`.
    pub cookie: u64,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<TracepointOpts> for libbpf_sys::bpf_tracepoint_opts {
    fn from(opts: TracepointOpts) -> Self {
        let TracepointOpts {
            cookie,
            _non_exhaustive,
        } = opts;

        #[allow(clippy::needless_update)]
        libbpf_sys::bpf_tracepoint_opts {
            sz: size_of::<Self>() as _,
            bpf_cookie: cookie,
            // bpf_tracepoint_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}

/// Options to optionally be provided when attaching to a raw tracepoint.
#[derive(Clone, Debug, Default)]
pub struct RawTracepointOpts {
    /// Custom user-provided value accessible through `bpf_get_attach_cookie`.
    pub cookie: u64,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<RawTracepointOpts> for libbpf_sys::bpf_raw_tracepoint_opts {
    fn from(opts: RawTracepointOpts) -> Self {
        let RawTracepointOpts {
            cookie,
            _non_exhaustive,
        } = opts;

        #[allow(clippy::needless_update)]
        libbpf_sys::bpf_raw_tracepoint_opts {
            sz: size_of::<Self>() as _,
            cookie,
            // bpf_raw_tracepoint_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}


/// Represents categories of Linux kernel tracepoints.
///
/// This enum provides a list of tracepoint categories that can be used with
/// BPF programs to attach to various kernel events.
#[derive(Debug)]
pub enum TracepointCategory {
    /// Alarm timer events.
    Alarmtimer,
    /// AMD CPU events.
    AmdCpu,
    /// ASoC (ALSA System on Chip) events.
    Asoc,
    /// AVC (Access Vector Cache) events.
    Avc,
    /// Block layer events.
    Block,
    /// BPF test run events.
    BpfTestRun,
    /// BPF trace events.
    BpfTrace,
    /// Bridge network device events.
    Bridge,
    /// CFG80211 (wireless configuration) events.
    Cfg80211,
    /// Cgroup subsystem events.
    Cgroup,
    /// Clock subsystem events.
    Clk,
    /// Memory compaction events.
    Compaction,
    /// Context tracking events.
    ContextTracking,
    /// CPU hotplug events.
    Cpuhp,
    /// ChromeOS EC (Embedded Controller) events.
    CrosEc,
    /// Call state distribution events.
    Csd,
    /// Device events.
    Dev,
    /// Device frequency events.
    Devfreq,
    /// Device link events.
    Devlink,
    /// DMA fence events.
    DmaFence,
    /// Direct Rendering Manager events.
    Drm,
    /// Error reporting events.
    ErrorReport,
    /// Exception events.
    Exceptions,
    /// Ext4 filesystem events.
    Ext4,
    /// IPv4 FIB (Forwarding Information Base) events.
    Fib,
    /// IPv6 FIB events.
    Fib6,
    /// File lock events.
    Filelock,
    /// File map events.
    Filemap,
    /// File system DAX events.
    FsDax,
    /// Ftrace events.
    Ftrace,
    /// GPIO (General Purpose Input/Output) events.
    Gpio,
    /// GPU scheduler events.
    GpuScheduler,
    /// Handshake events.
    Handshake,
    /// High Definition Audio events.
    Hda,
    /// HDA (High Definition Audio) controller events.
    HdaController,
    /// Intel HDA events.
    HdaIntel,
    /// Huge memory events.
    HugeMemory,
    /// Hardware monitor events.
    Hwmon,
    /// Hyper-V events.
    Hyperv,
    /// I2C (Inter-Integrated Circuit) events.
    I2c,
    /// Intel Graphics events.
    I915,
    /// ICMP (Internet Control Message Protocol) events.
    Icmp,
    /// Initialization call events.
    Initcall,
    /// Intel AVS (Audio Voice Speech) events.
    IntelAvs,
    /// Intel IOMMU (Input Output Memory Management Unit) events.
    IntelIommu,
    /// Intel ISH (Integrated Sensor Hub) events.
    IntelIsh,
    /// Interconnect events.
    Interconnect,
    /// IOCost events.
    Iocost,
    /// I/O mapping events.
    Iomap,
    /// IOMMU events.
    Iommu,
    /// IO uring events.
    IoUring,
    /// Inter-processor interrupt events.
    Ipi,
    /// IRQ (Interrupt Request) events.
    Irq,
    /// IRQ matrix events.
    IrqMatrix,
    /// IRQ vector events.
    IrqVectors,
    /// Intel wireless events.
    Iwlwifi,
    /// Intel wireless data events.
    IwlwifiData,
    /// Intel wireless I/O events.
    IwlwifiIo,
    /// Intel wireless message events.
    IwlwifiMsg,
    /// Intel wireless uCode events.
    IwlwifiUcode,
    /// Journaling Block Device v2 events.
    Jbd2,
    /// Kernel memory events.
    Kmem,
    /// Kernel samepage merging events.
    Ksm,
    /// Kernel-based Virtual Machine events.
    Kvm,
    /// KVM MMU (Memory Management Unit) events.
    Kvmmmu,
    /// Libata (library for ATA) events.
    Libata,
    /// Locking events.
    Lock,
    /// MAC80211 (wireless networking) events.
    Mac80211,
    /// MAC80211 message events.
    Mac80211Msg,
    /// Maple tree events.
    MapleTree,
    /// Machine check events.
    Mce,
    /// MCTP (Management Component Transport Protocol) events.
    Mctp,
    /// MDIO (Management Data Input/Output) events.
    Mdio,
    /// Management Engine Interface events.
    Mei,
    /// Memory migration events.
    Migrate,
    /// Memory mapping events.
    Mmap,
    /// Memory mapping lock events.
    MmapLock,
    /// MultiMediaCard events.
    Mmc,
    /// Module events.
    Module,
    /// Multipath TCP events.
    Mptcp,
    /// Model-Specific Register events.
    Msr,
    /// NAPI (New API) events.
    Napi,
    /// Neighbor subsystem events.
    Neigh,
    /// Networking events.
    Net,
    /// Netlink protocol events.
    Netlink,
    /// Non-Maskable Interrupt events.
    Nmi,
    /// Notifier chain events.
    Notifier,
    /// NVMe (Non-Volatile Memory express) events.
    Nvme,
    /// Out of memory events.
    Oom,
    /// OS noise events.
    Osnoise,
    /// Page isolation events.
    PageIsolation,
    /// Page mapping events.
    Pagemap,
    /// Page pool events.
    PagePool,
    /// Per-CPU events.
    Percpu,
    /// Power management events.
    Power,
    /// Printk (kernel printk) events.
    Printk,
    /// PWM (Pulse Width Modulation) events.
    Pwm,
    /// Queueing discipline events.
    Qdisc,
    /// Qualcomm RTR events.
    Qrtr,
    /// Reliability, availability, and serviceability events.
    Ras,
    /// Raw syscall events.
    RawSyscalls,
    /// Read-Copy-Update events.
    Rcu,
    /// Register map events.
    Regmap,
    /// Voltage regulator events.
    Regulator,
    /// Resource control events.
    Resctrl,
    /// Runtime power management events.
    Rpm,
    /// Restartable sequences events.
    Rseq,
    /// Real-time clock events.
    Rtc,
    /// RISC-V events.
    Rv,
    /// Scheduler events.
    Sched,
    /// SCSI (Small Computer System Interface) events.
    Scsi,
    /// Secure Digital events.
    Sd,
    /// Signal events.
    Signal,
    /// Socket buffer events.
    Skb,
    /// SMBus (System Management Bus) events.
    SmBus,
    /// Socket events.
    Sock,
    /// Sound Open Firmware events.
    Sof,
    /// Sound Open Firmware Intel events.
    SofIntel,
    /// SPI (Serial Peripheral Interface) events.
    Spi,
    /// Software I/O TLB events.
    SwIotlb,
    /// Synchronization trace events.
    SyncTrace,
    /// System call events.
    Syscalls,
    /// Task events.
    Task,
    /// TCP (Transmission Control Protocol) events.
    Tcp,
    /// Thermal management events.
    Thermal,
    /// Thermal power allocator events.
    ThermalPowerAllocator,
    /// Transparent huge pages events.
    Thp,
    /// Thunderbolt events.
    Thunderbolt,
    /// Timer events.
    Timer,
    /// Timer migration events.
    TimerMigration,
    /// Translation Lookaside Buffer events.
    Tlb,
    /// Transport Layer Security events.
    Tls,
    /// Universal Serial Bus Type-C Connector System Software Interface events.
    Ucsi,
    /// UDP (User Datagram Protocol) events.
    Udp,
    /// V4L2 (Video for Linux 2) events.
    V4l2,
    /// Video buffer 2 events.
    Vb2,
    /// Virtual memory allocation events.
    Vmalloc,
    /// Virtual memory scanner events.
    Vmscan,
    /// Virtual syscall events.
    Vsyscall,
    /// Watchdog events.
    Watchdog,
    /// Writeback throttling events.
    Wbt,
    /// Work queue events.
    Workqueue,
    /// Writeback events.
    Writeback,
    /// x86 floating-point unit events.
    X86Fpu,
    /// Express Data Path events.
    Xdp,
    /// Intel Xe graphics events.
    Xe,
    /// Xen hypervisor events.
    Xen,
    /// xHCI Host Controller events.
    XhciHcd,
    /// Custom type. Tracepoint category that is not predefined.
    Custom(String),
}

impl AsRef<str> for TracepointCategory {
    fn as_ref(&self) -> &str {
        match self {
            TracepointCategory::Alarmtimer => "alarmtimer",
            TracepointCategory::AmdCpu => "amd_cpu",
            TracepointCategory::Asoc => "asoc",
            TracepointCategory::Avc => "avc",
            TracepointCategory::Block => "block",
            TracepointCategory::BpfTestRun => "bpf_test_run",
            TracepointCategory::BpfTrace => "bpf_trace",
            TracepointCategory::Bridge => "bridge",
            TracepointCategory::Cfg80211 => "cfg80211",
            TracepointCategory::Cgroup => "cgroup",
            TracepointCategory::Clk => "clk",
            TracepointCategory::Compaction => "compaction",
            TracepointCategory::ContextTracking => "context_tracking",
            TracepointCategory::Cpuhp => "cpuhp",
            TracepointCategory::CrosEc => "cros_ec",
            TracepointCategory::Csd => "csd",
            TracepointCategory::Dev => "dev",
            TracepointCategory::Devfreq => "devfreq",
            TracepointCategory::Devlink => "devlink",
            TracepointCategory::DmaFence => "dma_fence",
            TracepointCategory::Drm => "drm",
            TracepointCategory::ErrorReport => "error_report",
            TracepointCategory::Exceptions => "exceptions",
            TracepointCategory::Ext4 => "ext4",
            TracepointCategory::Fib => "fib",
            TracepointCategory::Fib6 => "fib6",
            TracepointCategory::Filelock => "filelock",
            TracepointCategory::Filemap => "filemap",
            TracepointCategory::FsDax => "fs_dax",
            TracepointCategory::Ftrace => "ftrace",
            TracepointCategory::Gpio => "gpio",
            TracepointCategory::GpuScheduler => "gpu_scheduler",
            TracepointCategory::Handshake => "handshake",
            TracepointCategory::Hda => "hda",
            TracepointCategory::HdaController => "hda_controller",
            TracepointCategory::HdaIntel => "hda_intel",
            TracepointCategory::HugeMemory => "huge_memory",
            TracepointCategory::Hwmon => "hwmon",
            TracepointCategory::Hyperv => "hyperv",
            TracepointCategory::I2c => "i2c",
            TracepointCategory::I915 => "i915",
            TracepointCategory::Icmp => "icmp",
            TracepointCategory::Initcall => "initcall",
            TracepointCategory::IntelAvs => "intel_avs",
            TracepointCategory::IntelIommu => "intel_iommu",
            TracepointCategory::IntelIsh => "intel_ish",
            TracepointCategory::Interconnect => "interconnect",
            TracepointCategory::Iocost => "iocost",
            TracepointCategory::Iomap => "iomap",
            TracepointCategory::Iommu => "iommu",
            TracepointCategory::IoUring => "io_uring",
            TracepointCategory::Ipi => "ipi",
            TracepointCategory::Irq => "irq",
            TracepointCategory::IrqMatrix => "irq_matrix",
            TracepointCategory::IrqVectors => "irq_vectors",
            TracepointCategory::Iwlwifi => "iwlwifi",
            TracepointCategory::IwlwifiData => "iwlwifi_data",
            TracepointCategory::IwlwifiIo => "iwlwifi_io",
            TracepointCategory::IwlwifiMsg => "iwlwifi_msg",
            TracepointCategory::IwlwifiUcode => "iwlwifi_ucode",
            TracepointCategory::Jbd2 => "jbd2",
            TracepointCategory::Kmem => "kmem",
            TracepointCategory::Ksm => "ksm",
            TracepointCategory::Kvm => "kvm",
            TracepointCategory::Kvmmmu => "kvmmmu",
            TracepointCategory::Libata => "libata",
            TracepointCategory::Lock => "lock",
            TracepointCategory::Mac80211 => "mac80211",
            TracepointCategory::Mac80211Msg => "mac80211_msg",
            TracepointCategory::MapleTree => "maple_tree",
            TracepointCategory::Mce => "mce",
            TracepointCategory::Mctp => "mctp",
            TracepointCategory::Mdio => "mdio",
            TracepointCategory::Mei => "mei",
            TracepointCategory::Migrate => "migrate",
            TracepointCategory::Mmap => "mmap",
            TracepointCategory::MmapLock => "mmap_lock",
            TracepointCategory::Mmc => "mmc",
            TracepointCategory::Module => "module",
            TracepointCategory::Mptcp => "mptcp",
            TracepointCategory::Msr => "msr",
            TracepointCategory::Napi => "napi",
            TracepointCategory::Neigh => "neigh",
            TracepointCategory::Net => "net",
            TracepointCategory::Netlink => "netlink",
            TracepointCategory::Nmi => "nmi",
            TracepointCategory::Notifier => "notifier",
            TracepointCategory::Nvme => "nvme",
            TracepointCategory::Oom => "oom",
            TracepointCategory::Osnoise => "osnoise",
            TracepointCategory::PageIsolation => "page_isolation",
            TracepointCategory::Pagemap => "pagemap",
            TracepointCategory::PagePool => "page_pool",
            TracepointCategory::Percpu => "percpu",
            TracepointCategory::Power => "power",
            TracepointCategory::Printk => "printk",
            TracepointCategory::Pwm => "pwm",
            TracepointCategory::Qdisc => "qdisc",
            TracepointCategory::Qrtr => "qrtr",
            TracepointCategory::Ras => "ras",
            TracepointCategory::RawSyscalls => "raw_syscalls",
            TracepointCategory::Rcu => "rcu",
            TracepointCategory::Regmap => "regmap",
            TracepointCategory::Regulator => "regulator",
            TracepointCategory::Resctrl => "resctrl",
            TracepointCategory::Rpm => "rpm",
            TracepointCategory::Rseq => "rseq",
            TracepointCategory::Rtc => "rtc",
            TracepointCategory::Rv => "rv",
            TracepointCategory::Sched => "sched",
            TracepointCategory::Scsi => "scsi",
            TracepointCategory::Sd => "sd",
            TracepointCategory::Signal => "signal",
            TracepointCategory::Skb => "skb",
            TracepointCategory::SmBus => "smbus",
            TracepointCategory::Sock => "sock",
            TracepointCategory::Sof => "sof",
            TracepointCategory::SofIntel => "sof_intel",
            TracepointCategory::Spi => "spi",
            TracepointCategory::SwIotlb => "swiotlb",
            TracepointCategory::SyncTrace => "sync_trace",
            TracepointCategory::Syscalls => "syscalls",
            TracepointCategory::Task => "task",
            TracepointCategory::Tcp => "tcp",
            TracepointCategory::Thermal => "thermal",
            TracepointCategory::ThermalPowerAllocator => "thermal_power_allocator",
            TracepointCategory::Thp => "thp",
            TracepointCategory::Thunderbolt => "thunderbolt",
            TracepointCategory::Timer => "timer",
            TracepointCategory::TimerMigration => "timer_migration",
            TracepointCategory::Tlb => "tlb",
            TracepointCategory::Tls => "tls",
            TracepointCategory::Ucsi => "ucsi",
            TracepointCategory::Udp => "udp",
            TracepointCategory::V4l2 => "v4l2",
            TracepointCategory::Vb2 => "vb2",
            TracepointCategory::Vmalloc => "vmalloc",
            TracepointCategory::Vmscan => "vmscan",
            TracepointCategory::Vsyscall => "vsyscall",
            TracepointCategory::Watchdog => "watchdog",
            TracepointCategory::Wbt => "wbt",
            TracepointCategory::Workqueue => "workqueue",
            TracepointCategory::Writeback => "writeback",
            TracepointCategory::X86Fpu => "x86_fpu",
            TracepointCategory::Xdp => "xdp",
            TracepointCategory::Xe => "xe",
            TracepointCategory::Xen => "xen",
            TracepointCategory::XhciHcd => "xhci-hcd",
            TracepointCategory::Custom(category) => category,
        }
    }
}
