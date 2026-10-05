// Package box is a tiny gomobile-friendly wrapper around
// sing-box's experimental/libbox.
//
// All libbox API complexity lives here (checked by the Go compiler in CI).
// Java only sees: Start(config, tunFd, protector) -> BoxHandle, and
// BoxHandle.Stop(). The Protector interface is implemented in Java and
// must call VpnService.protect(fd).
package box

import (
	"errors"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// Protector is implemented by the Android app. It MUST call
// VpnService.protect(fd) so sing-box's own sockets bypass the TUN
// (otherwise traffic loops back into the VPN forever).
type Protector interface {
	Protect(fd int32)
}

// BoxHandle is a running sing-box instance.
type BoxHandle struct {
	service *libbox.BoxService
}

// Setup must be called once before Start. It tells sing-box where it may
// write files (cache.db, etc.). Pass the app's getFilesDir() and
// getCacheDir() from Java.
func Setup(basePath string, workingPath string, tempPath string) error {
	return libbox.Setup(&libbox.SetupOptions{
		BasePath:    basePath,
		WorkingPath: workingPath,
		TempPath:    tempPath,
	})
}

// Start launches sing-box with the given JSON config. tunFd is the raw fd
// from VpnService.Builder.establish().detachFd(). Java keeps ownership of
// the fd (we never close it here).
func Start(config string, tunFd int32, protector Protector) (*BoxHandle, error) {
	if protector == nil {
		return nil, errors.New("protector is nil")
	}
	svc, err := libbox.NewService(config, &androidPlatform{
		tunFd:     tunFd,
		protector: protector,
	})
	if err != nil {
		return nil, err
	}
	if err := svc.Start(); err != nil {
		return nil, err
	}
	return &BoxHandle{service: svc}, nil
}

// Stop shuts sing-box down.
func (h *BoxHandle) Stop() error {
	if h == nil || h.service == nil {
		return nil
	}
	return h.service.Close()
}

// ---------------------------------------------------------------------------
// androidPlatform implements libbox.PlatformInterface.
// Only OpenTun + AutoDetectInterfaceControl do real work; the rest are
// honest no-op stubs (v1 has no per-app routing UI, no interface monitor).
// ---------------------------------------------------------------------------

type androidPlatform struct {
	tunFd     int32
	protector Protector
}

func (p *androidPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	return true
}

func (p *androidPlatform) AutoDetectInterfaceControl(fd int32) error {
	p.protector.Protect(fd)
	return nil
}

// OpenTun hands sing-box the TUN fd that VpnService.Builder created.
// We do NOT create/configure anything here — the Builder already did.
func (p *androidPlatform) OpenTun(options libbox.TunOptions) (int32, error) {
	if p.tunFd <= 0 {
		return -1, errors.New("invalid tun fd")
	}
	return p.tunFd, nil
}

func (p *androidPlatform) WriteLog(message string) {
	// no-op: sing-box logs at warn level via its own config; avoid spam
}

func (p *androidPlatform) UseProcFS() bool { return false }

func (p *androidPlatform) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error) {
	return -1, errors.New("not implemented")
}

func (p *androidPlatform) PackageNameByUid(uid int32) (string, error) {
	return "", errors.New("not implemented")
}

func (p *androidPlatform) UIDByPackageName(packageName string) (int32, error) {
	return -1, errors.New("not implemented")
}

func (p *androidPlatform) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

func (p *androidPlatform) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

type emptyInterfaceIterator struct{}

func (e *emptyInterfaceIterator) Next() *libbox.NetworkInterface { return nil }
func (e *emptyInterfaceIterator) HasNext() bool                  { return false }

func (p *androidPlatform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return &emptyInterfaceIterator{}, nil
}

func (p *androidPlatform) UnderNetworkExtension() bool { return false }
func (p *androidPlatform) IncludeAllNetworks() bool   { return false }
func (p *androidPlatform) ReadWIFIState() *libbox.WIFIState {
	return nil
}
func (p *androidPlatform) ClearDNSCache() {}

func (p *androidPlatform) SendNotification(notification *libbox.Notification) error {
	return nil
}
