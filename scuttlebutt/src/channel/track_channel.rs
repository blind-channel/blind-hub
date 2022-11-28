// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::AbstractChannel;
use std::{
    io::{Read, Result, Write},
    sync::{Arc, Mutex}, ops::AddAssign,
};

/// A channel for tracking the number of bits read/written.
pub struct TrackChannel<R, W> {
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
    nbits_reader: Arc<Mutex<usize>>,
    nbits_writer: Arc<Mutex<usize>>,
}

impl<R: Read, W: Write> TrackChannel<R, W> {
    /// Make a new `TrackChannel` from a `reader` and a `writer`.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            nbits_reader: Arc::new(Mutex::new(0)),
            nbits_writer: Arc::new(Mutex::new(0))
        }
    }

    /// Clear the number of bits read/written.
    pub fn clear(&mut self) {
        self.nbits_reader = Arc::new(Mutex::new(0));
        self.nbits_writer = Arc::new(Mutex::new(0));
    }

    /// Return the number of kilobits written to the channel.
    pub fn kilobits_written(&self) -> f64 {
        self.nbits_writer.lock().unwrap().to_owned() as f64 / 1000.0
    }

    /// Return the number of kilobits read from the channel.
    pub fn kilobits_read(&self) -> f64 {
        self.nbits_reader.lock().unwrap().to_owned() as f64 / 1000.0
    }

    /// Return the total amount of communication on the channel.
    pub fn total_kilobits(&self) -> f64 {
        self.kilobits_written() + self.kilobits_read()
    }

    /// Return the number of kilobytes written to the channel.
    pub fn kilobytes_written(&self) -> f64 {
        self.nbits_writer.lock().unwrap().to_owned() as f64 / 8192.0
    }

    /// Return the number of kilobytes read from the channel.
    pub fn kilobytes_read(&self) -> f64 {
        self.nbits_reader.lock().unwrap().to_owned() as f64 / 8192.0
    }

    /// Return the total amount of communication on the channel as kilobytes.
    pub fn total_kilobytes(&self) -> f64 {
        self.kilobytes_written() + self.kilobytes_read()
    }
}

impl<R: Read, W: Write> AbstractChannel for TrackChannel<R, W> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.nbits_writer.lock().unwrap().add_assign(bytes.len() * 8);
        self.writer.lock().unwrap().write_all(bytes).unwrap();
        Ok(())
    }

    fn read_bytes(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        self.nbits_reader.lock().unwrap().add_assign(bytes.len() * 8);
        self.reader.lock().unwrap().read_exact(&mut bytes)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.lock().unwrap().flush()
    }

    fn clone(&self) -> Self {
        Self{
            reader: self.reader.clone(),
            writer: self.writer.clone(),
            nbits_reader: self.nbits_reader.clone(),
            nbits_writer: self.nbits_writer.clone()
        }
    }
}
