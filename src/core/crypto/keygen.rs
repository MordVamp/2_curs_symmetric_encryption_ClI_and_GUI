use crate::core::crypto::sha256::Sha256;
use std::f64::consts::PI;

// Конфигурируемые параметры
/// Количество отражений для генерации последовательности (влияет на энтропию ключа)
const REFLECTIONS: usize = 1000000;
/// Размер бильярдного стола (единичный квадрат)
const AREA_SIZE: f64 = 1.0;
/// Точность сравнения для учёта погрешностей вычислений
const EPSILON: f64 = 1e-9;

#[derive(Debug, Clone, Copy)]
struct Position {
    x: f64,
    y: f64,
}

#[derive(Debug, Clone, Copy)]
struct Direction {
    dx: f64,
    dy: f64,
}

#[derive(Debug, Clone, Copy)]
enum ReflectionSide {
    Left,
    Right,
    Top,
    Bottom,
}

impl ReflectionSide {
    /// Преобразует сторону отражения в соответствующий байт
    fn to_byte(self) -> u8 {
        match self {
            Self::Left => b'L',
            Self::Right => b'R',
            Self::Top => b'T',
            Self::Bottom => b'B',
        }
    }
}

pub fn derive_key(password: &[u8]) -> [u8; 32] {
    let reflection_sequence = simulate_billiard(password);
    let mut hasher = Sha256::new();
    hasher.update(&reflection_sequence);
    hasher.finalize()
}

/// Симулирует движение бильярдного шара для генерации последовательности отражений
fn simulate_billiard(password: &[u8]) -> Vec<u8> {
    let hash = initial_hash(password);
    let (x, y, angle) = parse_hash(&hash);
    let mut reflection_sequence = Vec::with_capacity(REFLECTIONS);

    let mut pos = Position { x, y };
    let mut dir = Direction {
        dx: angle.cos(),
        dy: angle.sin(),
    };

    // Защита от нулевого направления
    if dir.dx.abs() < f64::EPSILON && dir.dy.abs() < f64::EPSILON {
        dir.dx = f64::EPSILON;
        dir.dy = f64::EPSILON;
    }

    // Нормализация начального направления
    let length = dir.dx.hypot(dir.dy).max(f64::MIN_POSITIVE);
    dir.dx /= length;
    dir.dy /= length;

    for _ in 0..REFLECTIONS {
        let (side, new_pos) = calculate_reflection(pos, dir);
        reflection_sequence.push(side.to_byte());
        pos = new_pos;
        dir = update_direction(dir, side);
    }

    reflection_sequence
}

/// Вычисляет начальный хеш пароля
fn initial_hash(password: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.finalize()
}

/// Преобразует хеш в начальные параметры шара
fn parse_hash(hash: &[u8; 32]) -> (f64, f64, f64) {
    let x = to_normalized_f64(&hash[0..8]);
    let y = to_normalized_f64(&hash[8..16]);
    let angle = to_normalized_f64(&hash[16..24]) * 2.0 * PI;
    (x, y, angle)
}

/// Нормализует байты в число [0, 1]
fn to_normalized_f64(bytes: &[u8]) -> f64 {
    let arr = bytes.try_into().expect("Некорректная длина среза");
    u64::from_be_bytes(arr) as f64 / u64::MAX as f64
}

fn calculate_reflection(pos: Position, dir: Direction) -> (ReflectionSide, Position) {
    let Position { x, y } = pos;
    let Direction { dx, dy } = dir;

    let mut t = f64::INFINITY;
    let mut candidate_side = ReflectionSide::Left;

    // Расчет времени до столкновения с горизонтальными границами
    if dx > EPSILON {
        let tx = (AREA_SIZE - x) / dx;
        if tx < t {
            t = tx;
            candidate_side = ReflectionSide::Right;
        }
    } else if dx < -EPSILON {
        let tx = -x / dx;
        if tx < t {
            t = tx;
            candidate_side = ReflectionSide::Left;
        }
    }

    // Расчет времени до столкновения с вертикальными границами
    if dy > EPSILON {
        let ty = (AREA_SIZE - y) / dy;
        if ty < t {
            t = ty;
            candidate_side = ReflectionSide::Top;
        }
    } else if dy < -EPSILON {
        let ty = -y / dy;
        if ty < t {
            t = ty;
            candidate_side = ReflectionSide::Bottom;
        }
    }

    // Вычисление новой позиции с защитой от ошибок округления
    let new_x = (x + dx * t).clamp(0.0, AREA_SIZE);
    let new_y = (y + dy * t).clamp(0.0, AREA_SIZE);

    // Определение стороны с приоритетом угловых случаев
    let side = if (new_x - AREA_SIZE).abs() <= f64::EPSILON * 4.0 {
        ReflectionSide::Right
    } else if new_x <= f64::EPSILON * 4.0 {
        ReflectionSide::Left
    } else if (new_y - AREA_SIZE).abs() <= f64::EPSILON * 4.0 {
        ReflectionSide::Top
    } else if new_y <= f64::EPSILON * 4.0 {
        ReflectionSide::Bottom
    } else {
        candidate_side
    };

    (side, Position { x: new_x, y: new_y })
}
/// Обновляет направление после отражения
fn update_direction(dir: Direction, side: ReflectionSide) -> Direction {
    let mut new_dir = match side {
        ReflectionSide::Left | ReflectionSide::Right => Direction {
            dx: -dir.dx,
            dy: dir.dy,
        },
        ReflectionSide::Top | ReflectionSide::Bottom => Direction {
            dx: dir.dx,
            dy: -dir.dy,
        },
    };
    
    // Нормализация направления
    let length = (new_dir.dx.hypot(new_dir.dy)).max(f64::EPSILON);
    new_dir.dx /= length;
    new_dir.dy /= length;
    
    new_dir
}
