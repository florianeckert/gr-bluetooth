/* -*- c++ -*- */
/* 
 * Copyright 2020 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_BLUETOOTH_GR_BLUETOOTH_SINGLE_SNIFFER_IMPL_H
#define INCLUDED_BLUETOOTH_GR_BLUETOOTH_SINGLE_SNIFFER_IMPL_H

#include "gr_bluetooth/single_sniffer.h"
#include <gnuradio/digital/clock_recovery_mm_ff.h>
#include <gnuradio/analog/quadrature_demod_cf.h>
#include <gnuradio/digital/binary_slicer_fb.h>
#include "gr_bluetooth/no_filter_sniffer.h"

namespace gr {
namespace bluetooth {

    class single_sniffer_impl : virtual public single_sniffer
    {
        private:
            gr::analog::quadrature_demod_cf::sptr d_fm_demod;
            gr::digital::clock_recovery_mm_ff::sptr d_mm_cr;
            gr::digital::binary_slicer_fb::sptr d_bin_slice;
            no_filter_sniffer::sptr d_sniffer;

        public:
            single_sniffer_impl(double sample_rate, double center_freq, map_ptr piconets, std::mutex &piconets_mutex);
            ~single_sniffer_impl();
    };

} // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_GR_BLUETOOTH_SINGLE_SNIFFER_IMPL_H */

