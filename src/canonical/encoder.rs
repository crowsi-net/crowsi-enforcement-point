use crate::ActionBindingV1;

const DOMAIN: &[u8] = b"crowsi-control-canonical-v1\0";

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(artifact: &str) -> Self {
        let mut value = Self {
            bytes: DOMAIN.to_vec(),
        };
        value.text("artifact", artifact);
        value
    }

    pub(crate) fn text(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    pub(crate) fn number(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    pub(crate) fn boolean(&mut self, name: &str, value: bool) {
        self.bytes(name, &[u8::from(value)]);
    }

    pub(crate) fn optional_text(&mut self, name: &str, value: Option<&str>) {
        self.boolean(&format!("{name}.present"), value.is_some());
        if let Some(value) = value {
            self.text(name, value);
        }
    }

    pub(crate) fn strings(&mut self, name: &str, values: &[String]) {
        self.number(&format!("{name}.count"), values.len() as u64);
        for (index, value) in values.iter().enumerate() {
            self.text(&format!("{name}.{index}"), value);
        }
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        let name = name.as_bytes();
        let name_length = u16::try_from(name.len()).expect("canonical field name fits u16");
        let value_length = u64::try_from(value.len()).expect("canonical value fits u64");
        self.bytes.extend_from_slice(&name_length.to_be_bytes());
        self.bytes.extend_from_slice(name);
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) fn binding(encoder: &mut Encoder, value: &ActionBindingV1) {
    encoder.text("binding.audience", &value.audience);
    encoder.text("binding.resource", &value.resource);
    encoder.text("binding.action", value.action.code());
    encoder.text("binding.purpose", &value.purpose);
    encoder.text("binding.channel", value.channel.code());
}
