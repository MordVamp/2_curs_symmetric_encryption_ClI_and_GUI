use getrandom::getrandom;
use std::f64::consts::FRAC_1_PI;

pub struct RCTMPrng {
    x: f64,
    mu: f64,
    n1: f64,
    n2: f64,
    mu_half_mod: f64, //  предвычисленное значение
}

impl RCTMPrng {
    pub fn from_entropy() -> Result<Self, &'static str> {
        let mut buf = [0u8; 16];
        getrandom(&mut buf).map_err(|_| "Failed to get entropy")?;

        // Генерация mu с гарантией дробной части
        let mu_bits = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mu_int = (mu_bits % 98) + 2; // Целая часть [2, 99]
        let mu_frac = (mu_bits as f64) / (u64::MAX as f64); // Дробная часть [0, 1)
        let mu = mu_int as f64 + mu_frac;

        // Генерация x0 с гарантией (0, 1)
        let x0_bits = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let mut x0 = (x0_bits as f64 / u64::MAX as f64).fract();
        x0 = x0.clamp(f64::EPSILON, 1.0 - f64::EPSILON);

        Self::new(mu, x0)
    }

    pub fn new(mu: f64, x0: f64) -> Result<Self, &'static str> {
        if mu < 2.0 || mu >= 100.0 || (mu.floor() - mu).abs() < f64::EPSILON {
            return Err("mu должен быть в диапазоне [2, 100) и не быть целым числом");
        }
        if x0 <= 0.0 || x0 >= 1.0 {
            return Err("x0 должен быть в диапазоне (0, 1)");
        }

        let (n1, n2, mu_half_mod) = Self::calculate_regions(mu);
        Ok(Self {
            x: x0,
            mu,
            n1,
            n2,
            mu_half_mod, // Сохраняем предвычисленное значение
        })
    }

    fn calculate_regions(mu: f64) -> (f64, f64, f64) {
        let mu_half_mod = (mu * 0.5).fract();
        let temp = mu_half_mod;
        let n1 = 0.5 - temp / mu;
        let n2 = 0.5 + temp / mu;
        (n1, n2, mu_half_mod)
    }

    fn next_x(&mut self) {
        self.x = if (self.x >= self.n1) && (self.x <= self.n2) {
            if self.x < 0.5 {
                (self.mu * self.x).fract() / self.mu_half_mod
            } else {
                (self.mu * (1.0 - self.x)).fract() / self.mu_half_mod
            }
        } else {
            if self.x < 0.5 {
                (self.mu * self.x).fract()
            } else {
                (self.mu * (1.0 - self.x)).fract()
            }
        };
    }

    
    pub fn next_bit(&mut self) -> u8 {
        self.next_x();
        (self.x >= 0.5) as u8
    }

    pub fn next_byte(&mut self) -> u8 {
        let mut byte = 0;
        for i in 0..8 {
            byte |= self.next_bit() << (7 - i);
        }
        byte
    }

    pub fn fill_bytes(&mut self, buffer: &mut [u8]) {
        buffer.iter_mut().for_each(|byte| *byte = self.next_byte());
    }
}