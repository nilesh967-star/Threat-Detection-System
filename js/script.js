/**
 * ---------------------------------------
 * This demo was created using amCharts 5.
 *
 * For more information visit:
 * https://www.amcharts.com/
 *
 * Documentation is available at:
 * https://www.amcharts.com/docs/v5/
 * ---------------------------------------
 */

// Create root and chart
var root = am5.Root.new("chartdiv");

root.setThemes([
    am5themes_Animated.new(root)
]);

var chart = root.container.children.push(
    am5radar.RadarChart.new(root, {
        panX: false,
        panY: false,
        startAngle: -180,
        endAngle: 0,
        innerRadius: -26
    })
);

var axisRenderer = am5radar.AxisRendererCircular.new(root, {
    strokeOpacity: 0.1,
    minGridDistance: 30
});

axisRenderer.ticks.template.setAll({
    visible: true,
    strokeOpacity: 0.5
});

axisRenderer.grid.template.setAll({
    visible: false
});

var axis = chart.xAxes.push(
    am5xy.ValueAxis.new(root, {
        maxDeviation: 0,
        min: 0,
        max: 100,
        strictMinMax: true,
        renderer: axisRenderer
    })
);

function createRange(start, end, color, label) {

    var rangeDataItem = axis.makeDataItem({
        value: start,
        endValue: end
    });

    var range = axis.createAxisRange(rangeDataItem);

    rangeDataItem.get("axisFill").setAll({
        visible: true,
        fill: color,
        fillOpacity: 0.8
    });

    rangeDataItem.get("tick").setAll({
        visible: false
    });

    rangeDataItem.get("label").setAll({
        text: label,
        inside: true,
        radius: 8,
        fontSize: "0.9em",
        fill: am5.color(0xffffff)
    });

}

createRange(0, 70, am5.color(0x297373), "Safe");
createRange(70, 90, am5.color(0x946B49), "Warning");
createRange(90, 100, am5.color(0xff621f), "Danger");

// Add clock hand
var handDataItem = axis.makeDataItem({
    value: 0
});

var hand = handDataItem.set("bullet", am5xy.AxisBullet.new(root, {
    sprite: am5radar.ClockHand.new(root, {
        radius: am5.percent(99)
    })
}));

axis.createAxisRange(handDataItem);

handDataItem.get("grid").set("visible", false);
handDataItem.get("tick").set("visible", false);

setInterval(() => {
    handDataItem.animate({
        key: "value",
        to: Math.round(Math.random() * 100),
        duration: 800,
        easing: am5.ease.out(am5.ease.cubic)
    });
}, 2000);





// Dummy data for incoming and outgoing traffic
const incomingTraffic = [100, 150, 200, 250, 300, 350, 400];
const outgoingTraffic = [120, 170, 210, 260, 310, 360, 420];
const labels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

// Traffic chart configuration
const trafficCtx = document.getElementById('trafficCanvas').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
    type: 'line',
    data: {
        labels: labels,
        datasets: [{
            label: 'Incoming Traffic',
            data: incomingTraffic,
            backgroundColor: 'rgba(54, 162, 235, 0.2)',
            borderColor: 'rgba(54, 162, 235, 1)',
            borderWidth: 2,
            pointBackgroundColor: 'rgba(54, 162, 235, 1)',
            pointBorderColor: '#fff',
            pointBorderWidth: 2,
            pointRadius: 5,
            pointHoverRadius: 7
        }, {
            label: 'Outgoing Traffic',
            data: outgoingTraffic,
            backgroundColor: 'rgba(255, 99, 132, 0.2)',
            borderColor: 'rgba(255, 99, 132, 1)',
            borderWidth: 2,
            pointBackgroundColor: 'rgba(255, 99, 132, 1)',
            pointBorderColor: '#fff',
            pointBorderWidth: 2,
            pointRadius: 5,
            pointHoverRadius: 7
        }]
    },
    options: {
        scales: {
            yAxes: [{
                ticks: {
                    beginAtZero: true,
                    fontColor: '#666'
                },
                gridLines: {
                    color: '#ddd'
                }
            }],
            xAxes: [{
                ticks: {
                    fontColor: '#666'
                },
                gridLines: {
                    color: '#ddd'
                }
            }]
        },
        legend: {
            labels: {
                fontColor: '#333'
            }
        }
    }
});