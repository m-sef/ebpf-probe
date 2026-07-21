#ifndef PROBE_H
#define PROBE_H

class EBPFProbe {
public:
    void init();
private:
    void _attach_xdp_ingress();
    void _attach_tcx_egress();
};

#endif