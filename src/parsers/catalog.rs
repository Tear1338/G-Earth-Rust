//! Catalog index and page parsers for the beta-29 API.
use super::furniture::HProductType;
use crate::packet::{error, Packet, Result};

fn count(packet: &mut Packet) -> Result<usize> {
    let n = usize::try_from(packet.read_i32()?).map_err(|_| error("negative catalog count"))?;
    if n > 65_536 {
        return Err(error("catalog count exceeds limit"));
    }
    Ok(n)
}
fn strings(packet: &mut Packet) -> Result<Vec<String>> {
    let n = count(packet)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(packet.read_string()?);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HCatalogIndex {
    pub root: HCatalogPageIndex,
    pub new_additions_available: bool,
    pub catalog_type: String,
}
impl HCatalogIndex {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let mut budget = 65_536;
        Ok(Self {
            root: HCatalogPageIndex::read(packet, 0, &mut budget)?,
            new_additions_available: packet.read_bool()?,
            catalog_type: packet.read_string()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HCatalogPageIndex {
    pub visible: bool,
    pub icon: i32,
    pub page_id: i32,
    pub page_name: String,
    pub localization: String,
    pub offer_ids: Vec<i32>,
    pub children: Vec<Self>,
}
impl HCatalogPageIndex {
    fn read(packet: &mut Packet, depth: usize, budget: &mut usize) -> Result<Self> {
        if depth > 64 || *budget == 0 {
            return Err(error("catalog tree exceeds limit"));
        }
        *budget -= 1;
        let visible = packet.read_bool()?;
        let icon = packet.read_i32()?;
        let page_id = packet.read_i32()?;
        let page_name = packet.read_string()?;
        let localization = packet.read_string()?;
        let n = count(packet)?;
        let mut offer_ids = Vec::with_capacity(n);
        for _ in 0..n {
            offer_ids.push(packet.read_i32()?);
        }
        let n = count(packet)?;
        if n > *budget {
            return Err(error("catalog tree exceeds limit"));
        }
        let mut children = Vec::with_capacity(n);
        for _ in 0..n {
            children.push(Self::read(packet, depth + 1, budget)?);
        }
        Ok(Self {
            visible,
            icon,
            page_id,
            page_name,
            localization,
            offer_ids,
            children,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HProduct {
    pub product_type: HProductType,
    pub furni_class_id: Option<i32>,
    pub extra_param: String,
    pub product_count: i32,
    pub limited: Option<(i32, i32)>,
}
impl HProduct {
    fn read(packet: &mut Packet) -> Result<Self> {
        let product_type = HProductType::parse(&packet.read_string()?)?;
        if product_type == HProductType::Badge {
            return Ok(Self {
                product_type,
                furni_class_id: None,
                extra_param: packet.read_string()?,
                product_count: 1,
                limited: None,
            });
        }
        let furni_class_id = Some(packet.read_i32()?);
        let extra_param = packet.read_string()?;
        let product_count = packet.read_i32()?;
        let limited = if packet.read_bool()? {
            Some((packet.read_i32()?, packet.read_i32()?))
        } else {
            None
        };
        Ok(Self {
            product_type,
            furni_class_id,
            extra_param,
            product_count,
            limited,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HOffer {
    pub offer_id: i32,
    pub localization_id: String,
    pub rent: bool,
    pub credits: i32,
    pub activity_points: i32,
    pub activity_type: i32,
    pub silver: i32,
    pub giftable: bool,
    pub products: Vec<HProduct>,
    pub club_level: i32,
    pub bundle_allowed: bool,
    pub is_pet: bool,
    pub preview_image: String,
}
impl HOffer {
    fn read(packet: &mut Packet) -> Result<Self> {
        let offer_id = packet.read_i32()?;
        let localization_id = packet.read_string()?;
        let rent = packet.read_bool()?;
        let credits = packet.read_i32()?;
        let activity_points = packet.read_i32()?;
        let activity_type = packet.read_i32()?;
        let silver = packet.read_i32()?;
        let giftable = packet.read_bool()?;
        let n = count(packet)?;
        let mut products = Vec::with_capacity(n);
        for _ in 0..n {
            products.push(HProduct::read(packet)?);
        }
        Ok(Self {
            offer_id,
            localization_id,
            rent,
            credits,
            activity_points,
            activity_type,
            silver,
            giftable,
            products,
            club_level: packet.read_i32()?,
            bundle_allowed: packet.read_bool()?,
            is_pet: packet.read_bool()?,
            preview_image: packet.read_string()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HFrontPageTarget {
    Page(String),
    Offer(i32),
    Product(String),
    Other(i32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HFrontPageItem {
    pub position: i32,
    pub name: String,
    pub promo_image: String,
    pub target: HFrontPageTarget,
    pub expiration_time: i32,
}
impl HFrontPageItem {
    fn read(packet: &mut Packet) -> Result<Self> {
        let position = packet.read_i32()?;
        let name = packet.read_string()?;
        let promo_image = packet.read_string()?;
        let target = match packet.read_i32()? {
            0 => HFrontPageTarget::Page(packet.read_string()?),
            1 => HFrontPageTarget::Offer(packet.read_i32()?),
            2 => HFrontPageTarget::Product(packet.read_string()?),
            other => HFrontPageTarget::Other(other),
        };
        Ok(Self {
            position,
            name,
            promo_image,
            target,
            expiration_time: packet.read_i32()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HCatalogPage {
    pub page_id: i32,
    pub catalog_type: String,
    pub layout_code: String,
    pub images: Vec<String>,
    pub texts: Vec<String>,
    pub offers: Vec<HOffer>,
    pub offer_id: i32,
    pub accept_season_currency_as_credits: bool,
    pub front_page_items: Vec<HFrontPageItem>,
}
impl HCatalogPage {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let page_id = packet.read_i32()?;
        let catalog_type = packet.read_string()?;
        let layout_code = packet.read_string()?;
        let images = strings(packet)?;
        let texts = strings(packet)?;
        let n = count(packet)?;
        let mut offers = Vec::with_capacity(n);
        for _ in 0..n {
            offers.push(HOffer::read(packet)?);
        }
        let offer_id = packet.read_i32()?;
        let accept_season_currency_as_credits = packet.read_bool()?;
        let mut front_page_items = Vec::new();
        if packet.remaining() > 0 {
            let n = count(packet)?;
            front_page_items.reserve(n);
            for _ in 0..n {
                front_page_items.push(HFrontPageItem::read(packet)?);
            }
        }
        Ok(Self {
            page_id,
            catalog_type,
            layout_code,
            images,
            texts,
            offers,
            offer_id,
            accept_season_currency_as_credits,
            front_page_items,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_index_and_page_decode_optional_sections() {
        let mut index = Packet::new(1);
        index
            .put_bool(true)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_string("root")
            .unwrap()
            .put_string("loc")
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_i32(99)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_bool(true)
            .unwrap()
            .put_string("NORMAL")
            .unwrap();
        let index = HCatalogIndex::read(&mut index).unwrap();
        assert_eq!(index.root.offer_ids, vec![99]);
        assert_eq!(index.catalog_type, "NORMAL");
        let mut page = Packet::new(2);
        page.put_i32(7)
            .unwrap()
            .put_string("NORMAL")
            .unwrap()
            .put_string("default")
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(-1)
            .unwrap()
            .put_bool(false)
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_string("promo")
            .unwrap()
            .put_string("img")
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_i32(25)
            .unwrap()
            .put_i32(60)
            .unwrap();
        let page = HCatalogPage::read(&mut page).unwrap();
        assert_eq!(page.front_page_items[0].target, HFrontPageTarget::Offer(25));
    }
}
