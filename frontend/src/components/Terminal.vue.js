import { ref, onMounted, nextTick } from 'vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const output = ref('');
const command = ref('');
let socket = null;
const outputContainer = ref(null);
const connectWebSocket = () => {
    socket = new WebSocket(`ws://${window.location.hostname}:9000/ws`);
    socket.addEventListener('open', () => {
        console.log('WebSocket connection established');
    });
    socket.addEventListener('close', () => {
        console.log('WebSocket connection closed');
    });
    socket.addEventListener('message', async (event) => {
        output.value += event.data + '\n';
        await nextTick(); // Esperar a que el DOM se actualice
        scrollToBottom(); // Desplazar hacia abajo después de actualizar el DOM
    });
    socket.addEventListener('error', (error) => {
        console.error('WebSocket error:', error);
    });
};
const sendCommand = () => {
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(command.value);
        output.value += `multims_ ${command.value}\n`; // Agregar el comando ingresado al output
        command.value = ''; // Clear the input after sending
        nextTick(() => {
            scrollToBottom(); // Desplazar hacia abajo después de actualizar el DOM
        });
    }
    else {
        console.error('WebSocket is not connected');
    }
};
const scrollToBottom = () => {
    if (outputContainer.value) {
        outputContainer.value.scrollTop = outputContainer.value.scrollHeight;
    }
};
onMounted(() => {
    connectWebSocket();
});
const __VLS_fnComponent = (await import('vue')).defineComponent({});
let __VLS_functionalComponentProps;
function __VLS_template() {
    let __VLS_ctx;
    /* Components */
    let __VLS_otherComponents;
    let __VLS_own;
    let __VLS_localComponents;
    let __VLS_components;
    let __VLS_styleScopedClasses;
    // CSS variable injection 
    // CSS variable injection end 
    let __VLS_resolvedLocalAndGlobalComponents;
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("terminal") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("output") }, ref: ("outputContainer"), });
    // @ts-ignore
    (__VLS_ctx.outputContainer);
    __VLS_elementAsFunction(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
    __VLS_directiveFunction(__VLS_ctx.vHtml)((__VLS_ctx.output));
    // @ts-ignore
    [outputContainer, vHtml, output,];
    __VLS_elementAsFunction(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({ ...{ class: ("prompt") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({ ...{ class: ("blinking-cursor") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("input-container") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.input)({ ...{ onKeyup: (__VLS_ctx.sendCommand) }, value: ((__VLS_ctx.command)), type: ("text"), placeholder: ("Enter command here"), ...{ class: ("command-input") }, });
    // @ts-ignore
    [sendCommand, command,];
    __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.sendCommand) }, });
    // @ts-ignore
    [sendCommand,];
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['terminal'];
        __VLS_styleScopedClasses['output'];
        __VLS_styleScopedClasses['prompt'];
        __VLS_styleScopedClasses['blinking-cursor'];
        __VLS_styleScopedClasses['input-container'];
        __VLS_styleScopedClasses['command-input'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                output: output,
                command: command,
                outputContainer: outputContainer,
                sendCommand: sendCommand,
            };
        },
    });
}
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
;
